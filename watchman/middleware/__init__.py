"""Middleware package.

The project guide describes the "sentinel" as the eyes that watch traffic and
log files in real time, sitting between the request arriving and the app
handling it. This package holds the framework middleware entry points.
"""

from .base_middleware import WatchmanMiddleware

__all__ = ["WatchmanMiddleware"]
