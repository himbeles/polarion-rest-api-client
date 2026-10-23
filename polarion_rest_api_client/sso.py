# Copyright DB InfraGO AG and contributors
# SPDX-License-Identifier: Apache-2.0
"""Browser-owned Polarion SSO authentication for sync and async clients."""

from __future__ import annotations

import asyncio
import collections.abc as cabc
import concurrent.futures
import dataclasses
import hashlib
import math
import pathlib
import ssl
import threading
import typing as t
from contextlib import suppress

import httpx

from polarion_rest_api_client.errors import SsoAuthenticationError
from polarion_rest_api_client.open_api_client import Client

if t.TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Playwright

_TOKEN_SCRIPT = """() => {
    const owner = typeof window.getRestApiToken === 'function' ? window : window.top;
    return typeof owner.getRestApiToken === 'function' ? owner.getRestApiToken() : null;
}"""
_LOGIN_HINT = (
    "SSO login failed. Check the browser installation and SSO settings; "
    "use SsoConfig(headless=False) for interactive login/MFA."
)


@dataclasses.dataclass(frozen=True)
class SsoConfig:
    """Configure a dedicated persistent Playwright browser session.

    ``login_url`` and ``profile_dir`` default to values derived from the
    API endpoint. ``browser_executable`` overrides ``browser_channel``.
    ``timeout`` bounds browser startup and login separately, in seconds.
    """

    login_url: str | None = None
    headless: bool = True
    browser_channel: t.Literal["msedge", "chrome", "chromium"] = "msedge"
    browser_executable: pathlib.Path | None = None
    profile_dir: pathlib.Path | None = None
    timeout: float = 120.0

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError(
                "SSO timeout must be finite and greater than zero"
            )
        if self.browser_channel not in ("msedge", "chrome", "chromium"):
            raise ValueError("Unsupported SSO browser channel")

    def resolve(self, endpoint: str) -> SsoConfig:
        """Derive and validate instance-specific login and profile settings."""
        url = httpx.URL(endpoint)
        if (
            url.scheme != "https"
            or not url.host
            or url.userinfo
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "SSO requires an HTTPS endpoint without credentials"
            )
        path = url.path.rstrip("/")
        if path.endswith("/rest/v1"):
            context_path = path.removesuffix("/rest/v1")
        elif self.login_url is None:
            raise ValueError(
                "Set SsoConfig(login_url=...) for this API endpoint"
            )
        else:
            context_path = path
        login_url = self.login_url or str(
            url.copy_with(path=f"{context_path}/ssoLogin/Single-Sign-On")
        )
        login = httpx.URL(login_url)
        if login.userinfo or _origin(login) != _origin(url):
            raise ValueError("SSO login_url must use the Polarion origin")
        instance = f"{_origin(url)}{context_path}"
        profile = self.profile_dir or (
            pathlib.Path.home()
            / ".polarion-rest-api-client"
            / "sso"
            / hashlib.sha256(instance.encode()).hexdigest()[:16]
        )
        return dataclasses.replace(
            self,
            login_url=login_url,
            profile_dir=pathlib.Path(profile).expanduser(),
        )


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    return url.scheme, url.host, url.port


async def _start_playwright() -> Playwright:
    try:
        from playwright.async_api import async_playwright  # noqa: PLC0415
    except ImportError:
        raise SsoAuthenticationError(
            "SSO requires the optional dependency: polarion-rest-api-client[sso]"
        ) from None
    return await async_playwright().start()


class _BrowserSession:
    """Own all Playwright objects on the worker event loop."""

    def __init__(
        self,
        endpoint: str,
        config: SsoConfig,
        verify_ssl: ssl.SSLContext | bool,
    ) -> None:
        self.config = config
        self.origin = _origin(httpx.URL(endpoint))
        self.verify_ssl = verify_ssl
        self.playwright: Playwright | None = None
        self.context: BrowserContext | None = None
        self.token: str | None = None
        self.generation = 0
        self._failed_renewal: tuple[int, str] | None = None
        self.lock = asyncio.Lock()

    async def _start(self) -> None:
        if self.context is not None:
            return
        try:
            async with asyncio.timeout(self.config.timeout):
                self.playwright = await _start_playwright()
                assert self.config.profile_dir is not None
                executable = self.config.browser_executable
                self.context = (
                    await self.playwright.chromium.launch_persistent_context(
                        str(self.config.profile_dir),
                        headless=self.config.headless,
                        channel=None
                        if executable
                        else self.config.browser_channel,
                        executable_path=str(executable)
                        if executable
                        else None,
                        ignore_https_errors=self.verify_ssl is False,
                        timeout=self.config.timeout * 1000,
                    )
                )
            await self._authenticate()
        except BaseException:
            await self.close()
            raise

    async def _read_token(self) -> str | None:
        from playwright.async_api import Error  # noqa: PLC0415

        assert self.context is not None
        for page in self.context.pages:
            for frame in page.frames:
                if _origin(httpx.URL(frame.url)) != self.origin:
                    continue
                try:
                    token: object = await frame.evaluate(_TOKEN_SCRIPT)
                    if isinstance(token, str) and token.strip():
                        return token
                except Error:
                    continue
        return None

    async def _authenticate(self) -> None:
        from playwright.async_api import Error  # noqa: PLC0415

        assert self.context is not None
        self.token = None
        try:
            async with asyncio.timeout(self.config.timeout):
                page = (
                    self.context.pages[0]
                    if self.context.pages
                    else await self.context.new_page()
                )
                assert self.config.login_url is not None
                with suppress(Error):
                    await page.goto(
                        self.config.login_url,
                        wait_until="domcontentloaded",
                        timeout=self.config.timeout * 1000,
                    )
                while not self.token:
                    self.token = await self._read_token()
                    if not self.token:
                        await asyncio.sleep(0.5)
        except TimeoutError:
            raise SsoAuthenticationError(
                "SSO login timed out. Use SsoConfig(headless=False) for "
                "login/MFA; the landing page must expose getRestApiToken()."
            ) from None
        self.generation += 1
        self._failed_renewal = None

    async def headers(
        self, url: str, rejected_generation: int | None = None
    ) -> tuple[dict[str, str], int]:
        async with self.lock:
            try:
                if (
                    self._failed_renewal is not None
                    and rejected_generation == self._failed_renewal[0]
                ):
                    raise SsoAuthenticationError(self._failed_renewal[1])
                started = self.context is None
                await self._start()
                if not started:
                    if rejected_generation == self.generation:
                        await self._authenticate()
                    else:
                        token = await self._read_token()
                        if not token:
                            await self._authenticate()
                        elif token != self.token:
                            self.token = token
                            self.generation += 1
                assert self.context is not None
                cookies = await self.context.cookies([url])
                return {
                    "X-Polarion-REST-Token": self.token or "",
                    "Cookie": "; ".join(
                        f"{cookie['name']}={cookie['value']}"
                        for cookie in cookies
                    ),
                }, self.generation
            except asyncio.CancelledError:
                await self.close()
                raise
            except Exception as exc:
                await self.close()
                message = (
                    str(exc)
                    if isinstance(exc, SsoAuthenticationError)
                    else _LOGIN_HINT
                )
                if rejected_generation is not None:
                    self._failed_renewal = rejected_generation, message
                if isinstance(exc, SsoAuthenticationError):
                    raise
                raise SsoAuthenticationError(_LOGIN_HINT) from None

    async def close(self) -> None:
        context, self.context = self.context, None
        playwright, self.playwright = self.playwright, None
        self.token = None
        try:
            if context is not None:
                with suppress(Exception):
                    await context.close()
        finally:
            if playwright is not None:
                with suppress(Exception):
                    await playwright.stop()

    async def shutdown(self) -> None:
        async with self.lock:
            await self.close()


class _SsoWorker:
    """Share one browser between sync callers and arbitrary async loops."""

    def __init__(
        self,
        endpoint: str,
        config: SsoConfig,
        verify_ssl: ssl.SSLContext | bool,
    ) -> None:
        self.endpoint = endpoint
        self.config = config
        self.verify_ssl = verify_ssl
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session: _BrowserSession | None = None
        self._closed = False

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._session = _BrowserSession(
            self.endpoint, self.config, self.verify_ssl
        )
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    def submit(
        self, url: str, rejected_generation: int | None = None
    ) -> concurrent.futures.Future[tuple[dict[str, str], int]]:
        if _origin(httpx.URL(url)) != _origin(httpx.URL(self.endpoint)):
            raise SsoAuthenticationError(
                "Refusing to send SSO credentials to another origin"
            )
        with self._lock:
            if self._closed:
                raise SsoAuthenticationError("SSO client is closed")
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="polarion-sso", daemon=True
                )
                self._thread.start()
                self._ready.wait()
            assert self._loop is not None
            assert self._session is not None
            return asyncio.run_coroutine_threadsafe(
                self._session.headers(url, rejected_generation), self._loop
            )

    async def headers(
        self, url: str, rejected_generation: int | None = None
    ) -> tuple[dict[str, str], int]:
        future = await asyncio.to_thread(self.submit, url, rejected_generation)
        return await asyncio.wrap_future(future)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._thread is None:
                return
            assert self._loop is not None
            assert self._session is not None
            future = asyncio.run_coroutine_threadsafe(
                self._session.shutdown(), self._loop
            )
        try:
            future.result()
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join()


class _SsoAuth(httpx.Auth):
    def __init__(self, worker: _SsoWorker) -> None:
        self.worker = worker

    @staticmethod
    def _apply(request: httpx.Request, headers: dict[str, str]) -> None:
        request.headers.pop("Authorization", None)
        request.headers.update(headers)

    @staticmethod
    def _needs_login(response: httpx.Response) -> bool:
        return (
            response.status_code == httpx.codes.UNAUTHORIZED
            or response.is_redirect
        )

    @classmethod
    def _replay(
        cls, request: httpx.Request, headers: dict[str, str]
    ) -> httpx.Request:
        replay = httpx.Request(
            request.method,
            request.url,
            headers=request.headers,
            content=request.content,
            extensions=dict(request.extensions),
        )
        cls._apply(replay, headers)
        return replay

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> cabc.Generator[httpx.Request, httpx.Response, None]:
        headers, generation = self.worker.submit(str(request.url)).result()
        request.read()  # Buffer multipart/stream bodies for one exact replay.
        self._apply(request, headers)
        response = yield request
        if self._needs_login(response):
            response.read()
            headers, _ = self.worker.submit(
                str(request.url), generation
            ).result()
            response = yield self._replay(request, headers)
            if self._needs_login(response):
                response.close()
                raise SsoAuthenticationError(
                    "SSO authentication failed after renewal"
                )

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> cabc.AsyncGenerator[httpx.Request, httpx.Response]:
        headers, generation = await self.worker.headers(str(request.url))
        await request.aread()
        self._apply(request, headers)
        response = yield request
        if self._needs_login(response):
            await response.aread()
            headers, _ = await self.worker.headers(
                str(request.url), generation
            )
            response = yield self._replay(request, headers)
            if self._needs_login(response):
                await response.aclose()
                raise SsoAuthenticationError(
                    "SSO authentication failed after renewal"
                )


class _SsoClient(Client):
    """Guard every outgoing request, including explicitly followed redirects."""

    def _guard(self, request: httpx.Request) -> None:
        if _origin(request.url) != _origin(httpx.URL(self._base_url)):
            raise SsoAuthenticationError(
                "Refusing to send SSO credentials to another origin"
            )

    async def _async_guard(self, request: httpx.Request) -> None:
        self._guard(request)

    def get_httpx_client(self) -> httpx.Client:
        client = super().get_httpx_client()
        if self._guard not in client.event_hooks["request"]:
            client.event_hooks["request"].insert(0, self._guard)
        return client

    def get_async_httpx_client(self) -> httpx.AsyncClient:
        client = super().get_async_httpx_client()
        if self._async_guard not in client.event_hooks["request"]:
            client.event_hooks["request"].insert(0, self._async_guard)
        return client
