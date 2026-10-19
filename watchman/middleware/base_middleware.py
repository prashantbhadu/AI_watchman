"""Base middleware for AI Watchman.

The project guide's integration table shows FastAPI uses
``app.add_middleware(WatchmanMiddleware)``, Flask uses an extension, and
Django uses middleware at the top of ``MIDDLEWARE``. This module defines the
shared ASGI middleware skeleton; framework-specific wiring goes in
``fastapi_middleware.py``.
"""

from __future__ import annotations

import time
from typing import Awaitable, Callable

from ..models import Event, Source

RequestResponsePair = Callable[[object], Awaitable[object]]


class WatchmanMiddleware:
    """ASGI middleware that routes requests into the watchman pipeline.

    Framework adapters (FastAPI/Flask/Django) fill in detection, sending an
    :class:`Event` for each request so the dashboard and change log stay in
    sync.
    """

    def __init__(self, app: object, config: object | None = None):
        self.app = app
        self.config = config

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        start = time.monotonic()
        request_started = Event(
            source=Source.HTTP_REQUEST,
            request_path=scope.get("path"),
            detail="request received",
            evidence={"method": scope.get("method"), "path": scope.get("path")},
        )

        response = await self._handle_request(scope, receive, send)

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        request_completed = Event(
            source=Source.HTTP_REQUEST,
            request_path=scope.get("path"),
            detail="request completed",
            evidence={
                "method": scope.get("method"),
                "path": scope.get("path"),
                "status": getattr(response, "status_code", None),
                "elapsed_ms": elapsed_ms,
            },
        )
        return response

    async def _handle_request(self, scope, receive, send) -> object:
        raise NotImplementedError(
            "Subclass must implement framework-specific request handling"
        )
