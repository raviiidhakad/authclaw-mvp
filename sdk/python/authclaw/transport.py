"""Transport abstractions for the AuthClaw Python SDK."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, Protocol

from .client_contracts import TimeoutConfigurationContract
from .exceptions import ConnectionError, TimeoutError


@dataclass(frozen=True, slots=True)
class TransportRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    json_body: dict[str, object] | None = None
    timeout: TimeoutConfigurationContract | None = None


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    json_body: dict[str, object] | list[object] | None = None
    text: str = ""


@dataclass(frozen=True, slots=True)
class TransportStreamResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    chunks: Iterable[bytes | str] = field(default_factory=tuple)
    text: str = ""


class Transport(Protocol):
    """Synchronous transport interface used by AuthClawClient."""

    def send(self, request: TransportRequest) -> TransportResponse:
        """Send a request and return a transport response."""

    def stream(self, request: TransportRequest) -> TransportStreamResponse:
        """Send a streaming request and return an iterable stream response."""


class RequestsTransport:
    """Default synchronous transport backed by the optional requests package."""

    def __init__(self, session: object | None = None) -> None:
        self._session = session

    def send(self, request: TransportRequest) -> TransportResponse:
        requests_module = _load_requests()
        session = self._session or requests_module
        timeout = _requests_timeout(request.timeout)
        try:
            response = session.request(
                request.method,
                request.url,
                headers=request.headers,
                json=request.json_body,
                timeout=timeout,
            )
        except requests_module.exceptions.Timeout as exc:
            raise TimeoutError("AuthClaw request timed out") from exc
        except requests_module.exceptions.RequestException as exc:
            raise ConnectionError("AuthClaw request failed") from exc

        text = response.text or ""
        json_body: dict[str, object] | list[object] | None
        try:
            parsed = response.json()
            json_body = parsed if isinstance(parsed, dict | list) else None
        except ValueError:
            json_body = None

        return TransportResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            json_body=json_body,
            text=text,
        )

    def stream(self, request: TransportRequest) -> TransportStreamResponse:
        requests_module = _load_requests()
        session = self._session or requests_module
        timeout = _requests_timeout(request.timeout)
        try:
            response = session.request(
                request.method,
                request.url,
                headers=request.headers,
                json=request.json_body,
                timeout=timeout,
                stream=True,
            )
        except requests_module.exceptions.Timeout as exc:
            raise TimeoutError("AuthClaw streaming request timed out") from exc
        except requests_module.exceptions.RequestException as exc:
            raise ConnectionError("AuthClaw streaming request failed") from exc

        if response.status_code >= 400:
            return TransportStreamResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                chunks=(),
                text=response.text or "",
            )

        return TransportStreamResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            chunks=response.iter_content(chunk_size=None),
            text="",
        )


class MockTransport:
    """Deterministic in-memory transport for SDK tests."""

    def __init__(
        self,
        responses: list[TransportResponse] | None = None,
        stream_responses: list[TransportStreamResponse] | None = None,
    ) -> None:
        self.responses = list(responses or [])
        self.stream_responses = list(stream_responses or [])
        self.requests: list[TransportRequest] = []
        self.stream_requests: list[TransportRequest] = []

    def send(self, request: TransportRequest) -> TransportResponse:
        self.requests.append(request)
        if not self.responses:
            return TransportResponse(status_code=200, json_body={})
        return self.responses.pop(0)

    def stream(self, request: TransportRequest) -> TransportStreamResponse:
        self.stream_requests.append(request)
        if not self.stream_responses:
            return TransportStreamResponse(status_code=200, chunks=())
        return self.stream_responses.pop(0)


def _load_requests() -> object:
    try:
        import requests  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ConnectionError("The requests package is required for RequestsTransport") from exc
    return requests


def _requests_timeout(timeout: TimeoutConfigurationContract | None) -> float | tuple[float, float]:
    if timeout is None:
        return (10.0, 60.0)
    if timeout.total_timeout_seconds is not None:
        return timeout.total_timeout_seconds
    return (timeout.connect_timeout_seconds, timeout.read_timeout_seconds)


def dumps_json(payload: dict[str, object]) -> str:
    """Serialize SDK JSON payloads deterministically for tests and diagnostics."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
