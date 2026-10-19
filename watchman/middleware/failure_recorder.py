"""Failure recording.

The project guide's fail-open requirement says that if the Watchman engine
crashes, the host application must keep working: the middleware may not
abort a request, and it may not hide a crash from the caller either.

This helper records the context so that failures are easy to spot and easy to
report: every recorded failure carries the event that was being built and the
original exception, and the middleware can ask the recorder whether the
pipeline should keep running or let the request fail.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _now() -> float:
    """Return the current monotonic timestamp."""
    try:
        import time

        return time.monotonic()
    except Exception:
        return 0.0


@dataclass
class Failure:
    """One recorded failure of the Watchman pipeline."""

    event: object | None = None
    exception: BaseException | None = None
    source: str = "middleware"
    detail: str = ""
    timestamp: float = field(default_factory=lambda: _now())

    def was_success(self) -> bool:
        """False means the pipeline died and the middleware should fail open."""
        return self.exception is None and self.event is not None


class FailureRecorder:
    """Collect the recent failures of the Watchman pipeline.

    The middleware's fail-open logic consults this; the dashboard can scavenge
    it later for the "engine errors" panel.
    """

    def __init__(self, max_recent: int = 50) -> None:
        self._failures: list[Failure] = []
        self._max_recent = max_recent

    def record(self, failure: Failure) -> None:
        self._failures.append(failure)
        self._failures = self._failures[-self._max_recent:]

    def clear(self) -> None:
        self._failures.clear()

    def recent(self) -> list[Failure]:
        return list(self._failures)

    def was_pipeline_ok(self) -> bool:
        """Fail-open: the pipeline is only safe to trust when nothing died."""
        return all(failure.was_success() for failure in self._failures)

    def __bool__(self) -> bool:
        # A recorder is always truthy: it exists and is ready to collect
        # failures, even when the failure list is empty.
        return True
