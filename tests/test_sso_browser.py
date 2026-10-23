# Copyright DB InfraGO AG and contributors
# SPDX-License-Identifier: Apache-2.0
"""Opt-in Playwright test against an HTTPS Polarion simulation."""

from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from polarion_rest_api_client import PolarionClient, SsoConfig
from polarion_rest_api_client.open_api_client.api.projects import get_project
from tests.conftest import TEST_PROJECT_RESPONSE_JSON

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_POLARION_SSO_BROWSER_TESTS") != "1",
    reason="Set RUN_POLARION_SSO_BROWSER_TESTS=1 to run the local browser test",
)


@pytest.fixture
def simulated_polarion(tmp_path):
    pytest.importorskip("playwright.async_api")
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is needed to generate the local test certificate")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    state = types.SimpleNamespace(
        logins=0, last_login_cookie=None, requests=[], reject_next=False
    )
    project_json = TEST_PROJECT_RESPONSE_JSON.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/polarion/ssoLogin/Single-Sign-On":
                state.logins += 1
                state.last_login_cookie = self.headers.get("Cookie", "")
                token = f"dummy-token-{state.logins}"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header(
                    "Set-Cookie",
                    f"JSESSIONID=dummy-session-{state.logins}; "
                    "Path=/polarion; Secure; HttpOnly; Max-Age=3600",
                )
                self.end_headers()
                self.wfile.write(
                    (
                        "<html><script>window.getRestApiToken = () => "
                        + json.dumps(token)
                        + ";</script>Signed in</html>"
                    ).encode()
                )
            elif self.path == "/polarion/rest/v1/projects/PROJ":
                state.requests.append(dict(self.headers))
                valid = (
                    self.headers.get("X-Polarion-REST-Token")
                    == f"dummy-token-{state.logins}"
                    and self.headers.get("Cookie")
                    == f"JSESSIONID=dummy-session-{state.logins}"
                    and "Authorization" not in self.headers
                )
                reject = state.reject_next
                state.reject_next = False
                self.send_response(200 if valid and not reject else 401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    project_json if valid and not reject else b"{}"
                )
            else:
                self.send_response(404)
                self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.endpoint = f"https://127.0.0.1:{server.server_port}/polarion/rest/v1"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
async def test_real_browser_login_renewal_and_profile_reuse(
    simulated_polarion, tmp_path, is_async
):
    server = simulated_polarion
    config = SsoConfig(
        browser_channel="chromium",
        profile_dir=tmp_path / "profile",
        timeout=20,
    )
    async with PolarionClient(
        server.endpoint,
        auth_mode="sso",
        sso=config,
        verify_ssl=False,
        httpx_args={"trust_env": False},
    ) as client:
        for attempt in range(2):
            server.reject_next = attempt == 1
            if is_async:
                result = await get_project.asyncio_detailed(
                    "PROJ", client=client.client
                )
                assert result.status_code == 200
            else:
                assert client.generate_project_client("PROJ").exists()
        assert server.logins == 2
        assert len(server.requests) == 3
    assert not client._sso_worker._thread.is_alive()
    with PolarionClient(
        server.endpoint, auth_mode="sso", sso=config, verify_ssl=False
    ) as next_client:
        next_client.login()
        assert "JSESSIONID=dummy-session-2" in server.last_login_cookie
