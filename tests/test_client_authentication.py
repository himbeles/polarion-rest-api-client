# Copyright DB InfraGO AG and contributors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from unittest import mock

import httpx
import pytest
import pytest_httpx

import polarion_rest_api_client as polarion_api
from polarion_rest_api_client.open_api_client.api.projects import get_project
from tests.conftest import TEST_PROJECT_RESPONSE_JSON


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("auth_mode", [None, "bearer", "rest_token"])
@pytest.mark.parametrize("with_cookies", [False, True])
async def test_authentication_headers(
    httpx_mock: pytest_httpx.HTTPXMock,
    is_async,
    auth_mode,
    with_cookies,
):
    cookies = {"JSESSIONID": "dummy-session"} if with_cookies else None
    auth_options = {} if auth_mode is None else {"auth_mode": auth_mode}
    polarion_client = polarion_api.PolarionClient(
        polarion_api_endpoint="https://polarion.example.com/polarion/rest/v1",
        polarion_access_token="dummy-token",
        cookies=cookies,
        **auth_options,
    )
    with open(TEST_PROJECT_RESPONSE_JSON, encoding="utf8") as f:
        httpx_mock.add_response(json=json.load(f))

    if is_async:
        async with polarion_client.client:
            response = await get_project.asyncio_detailed(
                "PROJ", client=polarion_client.client
            )
    else:
        with polarion_client.client:
            response = get_project.sync_detailed(
                "PROJ", client=polarion_client.client
            )

    assert response.status_code == httpx.codes.OK
    request = httpx_mock.get_request()
    assert request is not None
    if auth_mode == "rest_token":
        assert request.headers["X-Polarion-REST-Token"] == "dummy-token"
        assert "Authorization" not in request.headers
    else:
        assert request.headers["Authorization"] == "Bearer dummy-token"
        assert "X-Polarion-REST-Token" not in request.headers
    if with_cookies:
        assert request.headers["Cookie"] == "JSESSIONID=dummy-session"
        assert cookies == {"JSESSIONID": "dummy-session"}
    else:
        assert "Cookie" not in request.headers


@mock.patch("polarion_rest_api_client.client.oa_client.AuthenticatedClient")
def test_invalid_auth_mode(mock_client):
    with pytest.raises(ValueError, match="auth_mode must be"):
        polarion_api.PolarionClient(
            polarion_api_endpoint="https://polarion.example.com",
            polarion_access_token="dummy-token",
            auth_mode="invalid",  # type: ignore[arg-type]
        )
    mock_client.assert_not_called()
