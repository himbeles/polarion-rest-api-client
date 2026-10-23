# Copyright DB InfraGO AG and contributors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import importlib
import sys
import threading
import types
from unittest import mock

import pytest

from polarion_rest_api_client import (
    PolarionClient,
    SsoAuthenticationError,
    SsoConfig,
)

ENDPOINT = "https://polarion.example.com/polarion/rest/v1"
REAL_SLEEP = asyncio.sleep


@pytest.fixture
def browser(monkeypatch):
    state = types.SimpleNamespace(token=None, logins=0, threads=set())

    async def goto(*_args, **_kwargs):
        state.logins += 1
        state.token = f"dummy-token-{state.logins}"

    async def evaluate(_script):
        state.threads.add(threading.get_ident())
        await REAL_SLEEP(0)
        return state.token

    state.frame = types.SimpleNamespace(
        url="https://polarion.example.com/polarion/",
        evaluate=mock.AsyncMock(side_effect=evaluate),
    )
    state.foreign_frame = types.SimpleNamespace(
        url="https://identity.example.com/",
        evaluate=mock.AsyncMock(return_value="foreign-token"),
    )
    state.page = types.SimpleNamespace(
        frames=[state.foreign_frame, state.frame],
        goto=mock.AsyncMock(side_effect=goto),
    )
    state.context = types.SimpleNamespace(
        pages=[state.page],
        new_page=mock.AsyncMock(return_value=state.page),
        cookies=mock.AsyncMock(
            return_value=[
                {"name": "JSESSIONID", "value": "dummy-session"},
            ]
        ),
        close=mock.AsyncMock(),
    )
    state.launch = mock.AsyncMock(return_value=state.context)
    state.playwright = types.SimpleNamespace(
        chromium=types.SimpleNamespace(launch_persistent_context=state.launch),
        stop=mock.AsyncMock(),
    )
    state.start = mock.AsyncMock(return_value=state.playwright)
    api = types.ModuleType("playwright.async_api")
    api.async_playwright = lambda: types.SimpleNamespace(start=state.start)
    api.Error = type("BrowserError", (Exception,), {})
    package = types.ModuleType("playwright")
    package.async_api = api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", api)
    return state


async def request(
    client, is_async, method="GET", *, url="/projects/PROJ", **kwargs
):
    if is_async:
        return await client.client.get_async_httpx_client().request(
            method, url, **kwargs
        )
    return client.client.get_httpx_client().request(method, url, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
async def test_lazy_login_and_reuse(browser, httpx_mock, is_async, tmp_path):
    client = PolarionClient(
        ENDPOINT, auth_mode="sso", sso=SsoConfig(profile_dir=tmp_path)
    )
    browser.start.assert_not_called()
    httpx_mock.add_response(json={}, is_reusable=True)
    async with client:
        for _ in range(2):
            assert (await request(client, is_async)).status_code == 200
    assert browser.logins == 1
    browser.start.assert_awaited_once()
    browser.foreign_frame.evaluate.assert_not_called()
    browser.context.cookies.assert_awaited_with([f"{ENDPOINT}/projects/PROJ"])
    launch = browser.launch.call_args
    assert launch.args == (str(tmp_path),)
    assert launch.kwargs["headless"] is True
    assert launch.kwargs["channel"] == "msedge"
    assert launch.kwargs["ignore_https_errors"] is False
    assert browser.threads != {threading.get_ident()}
    assert len(browser.threads) == 1
    for sent in httpx_mock.get_requests():
        assert sent.headers["X-Polarion-REST-Token"] == "dummy-token-1"
        assert sent.headers["Cookie"] == "JSESSIONID=dummy-session"
        assert "Authorization" not in sent.headers
    browser.context.close.assert_awaited_once()
    browser.playwright.stop.assert_awaited_once()
    assert not client._sso_worker._thread.is_alive()
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.parametrize("status", [401, 302])
async def test_renewal_replays_multipart(
    browser, httpx_mock, is_async, status
):
    httpx_mock.add_response(
        status_code=status,
        headers={"Location": "https://identity.example.com"},
    )
    httpx_mock.add_response(json={})
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        response = await request(
            client,
            is_async,
            "POST",
            data={"data": '{"dummy":true}'},
            files={"file": ("dummy.txt", b"dummy-content", "text/plain")},
        )
    assert response.status_code == 200
    assert browser.logins == 2
    first, second = httpx_mock.get_requests()
    assert first.content == second.content
    assert b"dummy-content" in second.content
    assert first.headers["X-Polarion-REST-Token"] == "dummy-token-1"
    assert second.headers["X-Polarion-REST-Token"] == "dummy-token-2"


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.parametrize("status", [401, 302])
async def test_exhausted_renewal_is_bounded(
    browser, httpx_mock, is_async, status
):
    httpx_mock.add_response(status_code=status, is_reusable=True)
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        with pytest.raises(SsoAuthenticationError, match="after renewal"):
            await request(client, is_async)
    assert len(httpx_mock.get_requests()) == 2
    assert browser.logins == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True])
async def test_forbidden_does_not_renew(browser, httpx_mock, is_async):
    httpx_mock.add_response(status_code=403)
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        assert (await request(client, is_async)).status_code == 403
    assert browser.logins == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True])
async def test_foreign_origin_never_sent(browser, httpx_mock, is_async):
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        with pytest.raises(SsoAuthenticationError, match="another origin"):
            await request(client, is_async, url="https://foreign.example.com/")
    browser.start.assert_not_called()
    assert not httpx_mock.get_requests()


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True])
async def test_explicit_redirect_cannot_leak(browser, httpx_mock, is_async):
    httpx_mock.add_response(
        status_code=302, headers={"Location": "https://foreign.example.com/"}
    )
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        with pytest.raises(SsoAuthenticationError, match="another origin"):
            await request(client, is_async, follow_redirects=True)
    assert len(httpx_mock.get_requests()) == 1
    assert browser.logins == 1


@pytest.mark.asyncio
async def test_concurrent_login_and_renewal(browser):
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        worker = client._sso_worker
        credentials = await asyncio.gather(
            *(worker.headers(ENDPOINT) for _ in range(8))
        )
        assert {generation for _, generation in credentials} == {1}
        assert browser.logins == 1
        credentials = await asyncio.gather(
            *(worker.headers(ENDPOINT, 1) for _ in range(8))
        )
        assert {generation for _, generation in credentials} == {2}
        assert browser.logins == 2


@pytest.mark.asyncio
async def test_expired_or_changed_browser_token(browser):
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        await client.async_login()
        browser.token = "dummy-rotated-token"
        headers, generation = await client._sso_worker.headers(ENDPOINT)
        assert headers["X-Polarion-REST-Token"] == browser.token
        assert generation == 2
        assert browser.logins == 1
        browser.token = None
        await client.async_login()
        assert browser.logins == 2


def test_sync_then_async_login_uses_one_worker(browser):
    with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        client.login()
        asyncio.run(client.async_login())
        asyncio.run(client.async_login())
        assert browser.logins == 1
    browser.context.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_login_does_not_block_event_loop(browser):
    entered = threading.Event()
    release = threading.Event()
    original = browser.page.goto.side_effect

    async def wait_for_release(*args, **kwargs):
        entered.set()
        await asyncio.to_thread(release.wait, 5)
        await original(*args, **kwargs)

    browser.page.goto.side_effect = wait_for_release
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        task = asyncio.create_task(client.async_login())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            assert not task.done()
        finally:
            release.set()
            await task


@pytest.mark.asyncio
async def test_cancelled_login_cleans_browser(browser):
    entered = threading.Event()

    async def wait_forever(*_args, **_kwargs):
        entered.set()
        await asyncio.Event().wait()

    browser.page.goto.side_effect = wait_forever
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        task = asyncio.create_task(client.async_login())
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    browser.context.close.assert_awaited_once()
    browser.playwright.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_login_timeout(browser):
    browser.page.goto.side_effect = None
    async with PolarionClient(
        ENDPOINT, auth_mode="sso", sso=SsoConfig(timeout=0.02)
    ) as client:
        with pytest.raises(SsoAuthenticationError, match="timed out"):
            await client.async_login()
    browser.context.close.assert_awaited_once()
    browser.playwright.stop.assert_awaited_once()


def test_startup_failure_is_sanitized(browser):
    browser.launch.side_effect = RuntimeError("private browser details")
    with (
        PolarionClient(ENDPOINT, auth_mode="sso") as client,
        pytest.raises(
            SsoAuthenticationError, match="browser installation"
        ) as error,
    ):
        client.login()
    assert "private browser details" not in str(error.value)
    browser.playwright.stop.assert_awaited_once()


def test_missing_optional_dependency(monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    with (
        PolarionClient(ENDPOINT, auth_mode="sso") as client,
        pytest.raises(SsoAuthenticationError, match=r"\[sso\]"),
    ):
        client.login()


def test_pat_does_not_import_playwright(monkeypatch):
    original = importlib.import_module
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    with PolarionClient(ENDPOINT, "dummy-token") as client:
        client.login()
        assert client._sso_worker is None
    assert original("polarion_rest_api_client").SsoConfig is SsoConfig


def test_config_derivation_and_profiles(tmp_path):
    resolved = SsoConfig().resolve(ENDPOINT)
    assert (
        resolved.login_url
        == "https://polarion.example.com/polarion/ssoLogin/Single-Sign-On"
    )
    assert (
        resolved.profile_dir == SsoConfig().resolve(f"{ENDPOINT}/").profile_dir
    )
    assert (
        resolved.profile_dir
        != SsoConfig()
        .resolve(ENDPOINT.replace("polarion.example", "other.example"))
        .profile_dir
    )
    assert (
        resolved.profile_dir
        != SsoConfig()
        .resolve(ENDPOINT.replace("/polarion/", "/other/"))
        .profile_dir
    )
    explicit = SsoConfig(
        login_url="https://polarion.example.com/login", profile_dir=tmp_path
    ).resolve("https://polarion.example.com/custom-api")
    assert explicit.profile_dir == tmp_path
    assert explicit.login_url.endswith("/login")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://polarion.example.com/rest/v1",
        "https://user:password@polarion.example.com/rest/v1",
        "https://polarion.example.com/custom-api",
        f"{ENDPOINT}?secret=value",
    ],
)
def test_invalid_sso_endpoint(endpoint):
    with pytest.raises(ValueError, match="SSO|SsoConfig"):
        PolarionClient(endpoint, auth_mode="sso")


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_timeout(timeout):
    with pytest.raises(ValueError, match="timeout"):
        SsoConfig(timeout=timeout)


def test_invalid_login_origin():
    with pytest.raises(ValueError, match="origin"):
        PolarionClient(
            ENDPOINT,
            auth_mode="sso",
            sso=SsoConfig(login_url="https://foreign.example.com/login"),
        )


@pytest.mark.parametrize(
    "options",
    [
        {"polarion_access_token": "dummy-token"},
        {"cookies": {}},
        {"httpx_args": {"auth": None}},
        {"httpx_args": {"follow_redirects": True}},
        {"httpx_args": {"headers": {"Authorization": "dummy-token"}}},
    ],
)
def test_conflicting_authentication(options):
    with pytest.raises(ValueError, match="SSO|SsoConfig"):
        PolarionClient(ENDPOINT, auth_mode="sso", **options)


@pytest.mark.parametrize("auth_mode", ["bearer", "rest_token"])
@pytest.mark.parametrize("token", [None, "", "   "])
def test_token_modes_require_token(auth_mode, token):
    with pytest.raises(ValueError, match="required"):
        PolarionClient(ENDPOINT, token, auth_mode=auth_mode)


def test_close_without_login_is_lazy(browser):
    client = PolarionClient(ENDPOINT, auth_mode="sso")
    client.close()
    client.close()
    browser.start.assert_not_called()
    with pytest.raises(RuntimeError, match="closed"):
        client.login()
    with pytest.raises(RuntimeError, match="closed"):
        client.__enter__()


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True])
async def test_high_level_retry_does_not_repeat_failed_auth(
    browser, httpx_mock, is_async
):
    httpx_mock.add_response(status_code=401, is_reusable=True)
    async with PolarionClient(ENDPOINT, auth_mode="sso") as client:
        items = client.generate_project_client("PROJ").work_items
        if is_async:
            with pytest.raises(SsoAuthenticationError, match="after renewal"):
                await items.async_get("WI-1")
        else:
            with pytest.raises(SsoAuthenticationError, match="after renewal"):
                items.get("WI-1")
    assert len(httpx_mock.get_requests()) == 2
    assert browser.logins == 2


@pytest.mark.asyncio
async def test_close_requires_async_cleanup_after_async_http(
    browser, httpx_mock
):
    httpx_mock.add_response(json={})
    client = PolarionClient(ENDPOINT, auth_mode="sso")
    try:
        await request(client, True)
        with pytest.raises(RuntimeError, match="aclose"):
            client.close()
    finally:
        await client.aclose()
    browser.context.close.assert_awaited_once()
    assert client.client._async_client.is_closed


@pytest.mark.asyncio
async def test_custom_browser_settings(browser, tmp_path):
    config = SsoConfig(
        headless=False,
        browser_channel="chrome",
        browser_executable=tmp_path / "browser",
        profile_dir=tmp_path,
        login_url="https://polarion.example.com/custom-login",
        timeout=30,
    )
    async with PolarionClient(
        ENDPOINT, auth_mode="sso", sso=config, verify_ssl=False
    ) as client:
        await client.async_login()
    kwargs = browser.launch.call_args.kwargs
    assert kwargs["headless"] is False
    assert kwargs["channel"] is None
    assert kwargs["executable_path"] == str(tmp_path / "browser")
    assert kwargs["ignore_https_errors"] is True
    assert kwargs["timeout"] == 30000
    assert browser.page.goto.call_args.args == (config.login_url,)


@pytest.mark.asyncio
async def test_concurrent_failed_renewal_is_coalesced(browser):
    async with PolarionClient(
        ENDPOINT, auth_mode="sso", sso=SsoConfig(timeout=0.02)
    ) as client:
        await client.async_login()
        browser.token = None
        original_login = browser.page.goto.side_effect
        browser.page.goto.side_effect = None
        results = await asyncio.gather(
            *(client._sso_worker.headers(ENDPOINT, 1) for _ in range(5)),
            return_exceptions=True,
        )
        assert all(
            isinstance(result, SsoAuthenticationError) for result in results
        )
        assert browser.page.goto.await_count == 2
        browser.page.goto.side_effect = original_login
        await client.async_login()
        _, generation = await client._sso_worker.headers(ENDPOINT, 1)
        assert generation == 2
        assert browser.page.goto.await_count == 3
