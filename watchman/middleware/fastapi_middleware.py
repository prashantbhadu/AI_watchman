"""FastAPI adapter for the ASGI middleware.

The project guide's integration table shows FastAPI using
``app.add_middleware(WatchmanMiddleware)``. This module wires the generic
ASGI middleware to a FastAPI app so every HTTP request (and WebSocket frame)
passes through the sentinel, the normalizer and the event builder.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

from ..models import Event, Source
from . import event_builder
from .base_middleware import WatchmanMiddleware as BaseWatchmanMiddleware
from .failure_recorder import Failure, FailureRecorder
from .normalizer import normalize
from .event_builder import build_event

RequestResponsePair = Callable[[Request], Awaitable[Any]]


class WatchmanMiddleware(BaseWatchmanMiddleware):
    """ASGI middleware that captures a standard Event for every request.

    Captures:
      - method, path, query string, headers, body
      - client IP address
      - response status so the dashboard can see what survived the request

    Fails open: if the Watchman pipeline (normalizer, event builder, scoring,
    change log) crashes, the host app keeps working and the failure is recorded
    for later inspection.
    """

    def __init__(
        self,
        app: Any,
        config: object | None = None,
        *,
        failure_recorder: FailureRecorder | None = None,
    ) -> None:
        super().__init__(app, config=config)
        self._failure_recorder = failure_recorder or FailureRecorder()
        self._capture_body = True

    # -- ASGI ----

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        start = time.monotonic()
        event = self._build_request_started_event(scope)

        try:
            response, event = await self._handle_request(scope, receive, send)
        except Exception as exc:  # pragma: no cover - fail-open path
            # The inner app crashed. Record the failure with the captured
            # event and let the exception propagate to the outer ASGI server
            # so the host app keeps responding through its own error
            # handling instead of being replaced by a Watchman-induced crash.
            event.detail = "request failed before completion"
            event_builder.record_failure(self._failure_recorder, event, exc)
            raise

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        self._record_completed_event(event, response, elapsed_ms)

        return response

    # -- Internal ----

    def _build_request_started_event(self, scope) -> Event:
        """Capture the request without the body yet; the body is captured
        separately in ``_handle_request`` so the event stays standard."""
        return Event(
            source=Source.HTTP_REQUEST,
            request_path=scope.get("path"),
            detail="request received",
            evidence={"method": scope.get("method"), "path": scope.get("path")},
        )

    async def _handle_request(self, scope, receive, send) -> tuple[Any, Event]:
        """Framework-specific handling for FastAPI/Starlette.

        Captures the full request (method, path, query, headers, body, IP),
        normalizes the input and hands one standard Event to the pipeline.

        Returns the ASGI response and the captured Event so the caller can
        record the completion event.
        """
        request = Request(scope, receive=receive, send=send)

        method = request.method
        path = request.url.path
        query = request.url.query
        headers = {k: v for k, v in request.headers.items()}
        ip_address = self._client_ip(request)
        user_agent = headers.get("user-agent")

        body = b""
        if self._capture_body:
            body = await request.body()
            event = build_event(
                recorder=self._failure_recorder,
                method=method,
                path=path,
                query=query,
                headers=headers,
                body=body.decode("utf-8", errors="replace"),
                ip_address=ip_address,
                user_agent=user_agent,
            )
        else:
            event = self._build_request_started_event(scope)

        self._run_pipeline(event)

        response = await self._call_next(request)
        return response, event

    def _client_ip(self, request: Request) -> str | None:
        """Best-effort client IP, honoring ``X-Forwarded-For`` behind proxies."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else None

    async def _call_next(self, request: Request) -> Any:
        """Call the next ASGI app in the stack."""
        scope = request.scope
        receive = request.receive
        send = request._send
        response = await self.app(scope, receive, send)
        return response

    def _run_pipeline(self, event: Event) -> None:
        """Run the Watchman pipeline for this event.

        In the full package this would call the threat engine, jailbreak guard,
        policy engine and change log. Here the process is deliberately split so
        a crash in any one stage fails open instead of aborting the request.
        """
        try:
            self._normalizer_and_build(event)
        except Exception as exc:  # pragma: no cover - fail-open path
            event_builder.record_failure(self._failure_recorder, event, exc)

    def _normalizer_and_build(self, event: Event) -> None:
        """Normalizes the captured request and builds the final Event.

        The event body and evidence are normalized so attackers cannot hide
        payloads behind encoding tricks (``%61%73%73%65%72%74`` ->
        ``assault``), and the pipeline fails open instead of crashing.
        """
        evidence = event.evidence or {}
        evidence["method"] = normalize(evidence.get("method", ""))
        evidence["path"] = normalize(evidence.get("path", ""))
        evidence["query"] = normalize(evidence.get("query", ""))
        evidence["headers"] = {
            normalize(str(k)): normalize(str(v)) for k, v in (evidence.get("headers") or {}).items()
        }
        evidence["body"] = normalize(evidence.get("body", ""))

    def _record_completed_event(self, event: Event, response: Any, elapsed_ms: float) -> None:
        """Record the request-completed event with the response status."""
        event.detail = "request completed"
        event.evidence |= {
            "status": getattr(response, "status_code", None),
            "elapsed_ms": elapsed_ms,
        }
        self._failure_recorder.record(
            Failure(
                event=event,
                exception=None,
                source="sentinel",
                detail="request completed",
                timestamp=time.monotonic(),
            )
        )

    def pipeline_ok(self) -> bool:
        """Fail-open: the pipeline is only trustworthy if nothing died."""
        return self._failure_recorder.was_pipeline_ok()
