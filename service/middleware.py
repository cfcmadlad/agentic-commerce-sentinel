"""Request logging and rate limiting for the API service.

Both are hand-rolled rather than pulled from a dependency: a fixed-window
per-client counter and a per-request log line are a few lines each, and
adding a dependency (and its own transitive closure) for something this
small would cost more than it saves. This is an explicit, stated tradeoff:
the limiter is in-memory and per-process, so it does not coordinate across
multiple worker processes or survive a restart -- correct for the
single-process deployment this service is documented for, not a
distributed rate limiter.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

DEFAULT_MAX_REQUESTS_PER_WINDOW = 60
DEFAULT_WINDOW_SECONDS = 60.0


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs method, path, status code, and latency for every request."""

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Times and logs one request/response cycle.

        Args:
            request: The incoming request.
            call_next: The next handler in the middleware chain.

        Returns:
            The response, unmodified.
        """
        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info(
            "%s %s -> %d (%.1fms)", request.method, request.url.path, response.status_code, elapsed_ms
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """A fixed-window per-client-IP request limiter.

    Attributes:
        _max_requests: Requests allowed per window, per client IP.
        _window_seconds: Window length in seconds.
        _buckets: Per-IP (count, window_start) state.
    """

    def __init__(
        self,
        app: object,
        max_requests: int = DEFAULT_MAX_REQUESTS_PER_WINDOW,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        """Initializes the limiter.

        Args:
            app: The ASGI application to wrap.
            max_requests: Requests allowed per window, per client IP.
            window_seconds: Window length in seconds.
        """
        super().__init__(app)  # type: ignore[arg-type]
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._buckets: dict[str, tuple[int, float]] = {}

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Rejects a request with 429 if its client IP is over the window limit.

        Args:
            request: The incoming request.
            call_next: The next handler in the middleware chain.

        Returns:
            A 429 JSON response if the caller is over the limit, otherwise
            the wrapped handler's response.
        """
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        count, window_start = self._buckets.get(client_ip, (0, now))
        if now - window_start >= self._window_seconds:
            count, window_start = 0, now
        count += 1
        self._buckets[client_ip] = (count, window_start)

        if count > self._max_requests:
            logger.warning("rate limit exceeded for %s (%d requests)", client_ip, count)
            return JSONResponse(
                {"detail": f"rate limit exceeded: max {self._max_requests} requests per {self._window_seconds:.0f}s"},
                status_code=429,
            )
        return await call_next(request)
