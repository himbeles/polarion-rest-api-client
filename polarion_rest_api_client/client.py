# Copyright DB InfraGO AG and contributors
# SPDX-License-Identifier: Apache-2.0
"""The overall Polarion Client which handles the HTTP session, auth etc."""

from __future__ import annotations

import asyncio
import ssl
import typing as t

import truststore

import polarion_rest_api_client.open_api_client as oa_client
from polarion_rest_api_client import data_models as dm
from polarion_rest_api_client.clients import projects
from polarion_rest_api_client.sso import (
    SsoConfig,
    _SsoAuth,
    _SsoClient,
    _SsoWorker,
)

WorkItemType = t.TypeVar("WorkItemType", bound=dm.WorkItem)


class DefaultFields:
    """A class to define default values for the fields parameter."""

    _workitems: str = "@basic"
    _linkedworkitems: str = "id,role,suspect"
    _workitem_attachments: str = "@basic"
    _documents: str = "@basic"
    _testrecords: str = "@basic"
    _testruns: str = "@basic"
    _teststeps: str = "@basic"
    _testparameters: str = "@all"

    @property
    def workitems(self) -> dict[str, str]:
        """Return the fields dict for workitems."""
        return {"workitems": self._workitems}

    @workitems.setter
    def workitems(self, value: str) -> None:
        self._workitems = value

    @property
    def linkedworkitems(self) -> dict[str, str]:
        """Return the fields dict for linkedworkitems."""
        return {"linkedworkitems": self._linkedworkitems}

    @linkedworkitems.setter
    def linkedworkitems(self, value: str) -> None:
        self._linkedworkitems = value

    @property
    def workitem_attachments(self) -> dict[str, str]:
        """Return the fields dict for workitem_attachments."""
        return {"workitem_attachments": self._workitem_attachments}

    @workitem_attachments.setter
    def workitem_attachments(self, value: str) -> None:
        self._workitem_attachments = value

    @property
    def documents(self) -> dict[str, str]:
        """Return the fields dict for document."""
        return {"documents": self._documents}

    @documents.setter
    def documents(self, value: str) -> None:
        self._documents = value

    @property
    def testruns(self) -> dict[str, str]:
        """Return the fields dict for testruns."""
        return {"testruns": self._testruns}

    @testruns.setter
    def testruns(self, value: str) -> None:
        self._testruns = value

    @property
    def testrecords(self) -> dict[str, str]:
        """Return the fields dict for testrecords."""
        return {"testrecords": self._testrecords}

    @testrecords.setter
    def testrecords(self, value: str) -> None:
        self._testrecords = value

    @property
    def teststeps(self) -> dict[str, str]:
        """Return the fields dict for teststeps."""
        return {"teststeps": self._teststeps}

    @teststeps.setter
    def teststeps(self, value: str) -> None:
        self._teststeps = value

    @property
    def testparameters(self) -> dict[str, str]:
        """Return the fields dict for testparameters."""
        return {"testparameters": self._testparameters}

    @testparameters.setter
    def testparameters(self, value: str) -> None:
        self._testparameters = value

    @property
    def all_types(self) -> dict[str, str]:
        """Return all fields dicts merged together."""
        return (
            self.workitem_attachments
            | self.workitems
            | self.linkedworkitems
            | self.documents
            | self.testruns
            | self.testrecords
            | self.testparameters
        )


class PolarionClient:
    """The overall, project independent Polarion client.

    Authentication defaults to a personal access token sent as
    ``Authorization: Bearer <token>``. Set ``auth_mode="sso"`` for managed
    Playwright login and renewal using ``X-Polarion-REST-Token`` and browser
    cookies. Configure the browser with ``sso=SsoConfig(...)`` and use a
    context manager to close its session. ``auth_mode="rest_token"`` accepts
    a manually supplied REST token and cookies instead.
    """

    def __init__(
        self,
        polarion_api_endpoint: str,
        polarion_access_token: str | None = None,
        httpx_args: dict[str, t.Any] | None = None,
        batch_size: int = 100,
        page_size: int = 100,
        max_content_size: int = 2 * 1024**2,
        verify_ssl: ssl.SSLContext | bool | None = None,
        max_async_in_flight_requests: int = 4,
        *,
        auth_mode: t.Literal["bearer", "rest_token", "sso"] = "bearer",
        cookies: dict[str, str] | None = None,
        sso: SsoConfig | None = None,
    ):
        if auth_mode not in ("bearer", "rest_token", "sso"):
            raise ValueError(
                "auth_mode must be 'bearer', 'rest_token' or 'sso'"
            )
        if auth_mode != "sso" and (
            not polarion_access_token or not polarion_access_token.strip()
        ):
            raise ValueError(
                "polarion_access_token is required in token modes"
            )
        if auth_mode != "sso" and sso is not None:
            raise ValueError("SsoConfig requires auth_mode='sso'")
        httpx_args = dict(httpx_args or {})
        sso_config = None
        if auth_mode == "sso":
            if polarion_access_token is not None or cookies is not None:
                raise ValueError("SSO manages its own token and cookies")
            if {
                "auth",
                "cookies",
                "headers",
                "follow_redirects",
            } & httpx_args.keys():
                raise ValueError(
                    "SSO manages authentication, cookies, headers and redirects"
                )
            sso_config = (sso or SsoConfig()).resolve(polarion_api_endpoint)
        if verify_ssl is None:
            verify_ssl = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._sso_worker: _SsoWorker | None = None
        self._closed = False
        self.client: oa_client.Client | oa_client.AuthenticatedClient
        if sso_config is not None:
            self._sso_worker = _SsoWorker(
                polarion_api_endpoint, sso_config, verify_ssl
            )
            httpx_args["auth"] = _SsoAuth(self._sso_worker)
            self.client = _SsoClient(
                polarion_api_endpoint,
                verify_ssl=verify_ssl,
                httpx_args=httpx_args,
            )
        else:
            assert polarion_access_token is not None
            self.client = oa_client.AuthenticatedClient(
                polarion_api_endpoint,
                polarion_access_token,
                auth_header_name=(
                    "X-Polarion-REST-Token"
                    if auth_mode == "rest_token"
                    else "Authorization"
                ),
                prefix="" if auth_mode == "rest_token" else "Bearer",
                cookies=dict(cookies) if cookies is not None else {},
                verify_ssl=verify_ssl,
                httpx_args=httpx_args,
            )
        self.max_async_in_flight_requests = max_async_in_flight_requests
        self.semaphore = asyncio.Semaphore(max_async_in_flight_requests)
        self.batch_size = batch_size
        self.page_size = page_size
        self.max_content_size = max_content_size
        self.default_fields = DefaultFields()

    def login(self) -> None:
        """Initialize SSO now instead of waiting for the first API request."""
        if self._closed:
            raise RuntimeError("Polarion client is closed")
        if self._sso_worker is not None:
            self._sso_worker.submit(self._sso_worker.endpoint).result()

    async def async_login(self) -> None:
        """Initialize SSO without blocking the caller's event loop."""
        if self._closed:
            raise RuntimeError("Polarion client is closed")
        if self._sso_worker is not None:
            await self._sso_worker.headers(self._sso_worker.endpoint)

    def close(self) -> None:
        """Close synchronous HTTP and browser resources.

        If asynchronous HTTP was used, call ``aclose()`` on its event loop
        instead, so that its connections can also be closed safely.
        """
        if (
            self.client._async_client is not None
            and not self.client._async_client.is_closed
        ):
            raise RuntimeError(
                "Use await client.aclose() after async HTTP calls"
            )
        self._closed = True
        try:
            if self.client._client is not None:
                self.client._client.close()
        finally:
            if self._sso_worker is not None:
                self._sso_worker.close()

    async def aclose(self) -> None:
        """Close HTTP connections on their event loop and stop the browser."""
        self._closed = True
        try:
            if self.client._async_client is not None:
                await self.client._async_client.aclose()
        finally:
            try:
                if self.client._client is not None:
                    await asyncio.to_thread(self.client._client.close)
            finally:
                if self._sso_worker is not None:
                    await asyncio.to_thread(self._sso_worker.close)

    def __enter__(self) -> t.Self:
        if self._closed:
            raise RuntimeError("Polarion client is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    async def __aenter__(self) -> t.Self:
        return self.__enter__()

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    def generate_project_client(
        self,
        project_id: str,
        delete_status: str | None = None,
    ) -> projects.ProjectClient:
        """Return a client for a specific project."""
        return projects.ProjectClient(project_id, self, delete_status)
