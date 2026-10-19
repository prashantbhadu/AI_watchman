"""Event builder.

The project guide's "Conversion of each request into one standard Event
object" step says that raw request details should be passed through the
normalizer and packed into the shared :class:`watchman.models.Event` that the
dashboard, change log and scoring module all understand.

One Event says where the data came from (``Source``), how severe it is,
which attack family it belongs to, what the raw evidence was and, for HTTP
traffic, the path, IP and user agent that arrived at the sentinel.
"""

from __future__ import annotations

from typing import Any

from ..models import DetectionType, Event, Source, ThreatCategory

from .normalizer import normalize
from .failure_recorder import Failure, FailureRecorder


def build_event(
    *,
    recorder: FailureRecorder,
    method: str,
    path: str,
    query: str = "",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    source: Source = Source.HTTP_REQUEST,
    component: str = "sentinel",
) -> Event:
    """Build one standard Event from the raw ASGI request details.

    The evidence dict is normalized so that ``%61%73%73%65%72%74`` and
    ``admin`` are seen as the same thing, and the event is marked as
    processed-by-Watchman so a downstream component never has to guess.
    """
    normalized_headers = {
        normalize(key): normalize(value) for key, value in (headers or {}).items()
    }
    normalized_query = normalize(query)
    normalized_path = normalize(path)
    normalized_body = normalize(body)

    evidence: dict[str, Any] = {
        "method": method,
        "path": normalized_path,
        "query": normalized_query,
        "headers": normalized_headers,
        "body": normalized_body,
        "source": source.value,
    }

    if ip_address is not None:
        evidence["ip_address"] = normalize(ip_address)
    if user_agent is not None:
        evidence["user_agent"] = normalize(user_agent)

    return Event(
        source=source,
        component=component,
        severity="0",
        threat_category=ThreatCategory.UNKNOWN,
        detection_type=DetectionType.REGEX_SIGNATURE,
        detail="request captured by sentinel",
        evidence=evidence,
        ip_address=ip_address,
        user_agent=user_agent,
        request_path=normalized_path,
        log_line=None,
    )


def record_failure(recorder: FailureRecorder, event: Event, exception: BaseException) -> None:
    """Record a failure so the middleware can fail open."""
    recorder.record(
        Failure(
            event=event,
            exception=exception,
            source="sentinel",
            detail="watchman pipeline failed",
        )
    )
