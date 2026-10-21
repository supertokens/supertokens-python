# Copyright (c) 2026, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
Test-only timing middleware for the e2e and integration test servers.

Enabled by setting `LOG_TEST_TIMINGS=1` in the env before any test-server
init code runs. Two streams are emitted to stdout, one line each:

    [QUERIER] POST /recipe/oauth/auth 47.3ms          # outbound to core
    [REQUEST] POST /auth/signin 200 121.4ms           # inbound to test server

Test-server stdout is already captured to AUTH_REACT__LOG_DIR/<framework>.log
(or the website-test equivalent), so after a CI run the artifact contains
the timing data. Aggregate with grep + awk to find the slowest calls.

This module deliberately doesn't change SDK behavior when disabled — the
`install_*` helpers no-op unless the env var is set.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable


def _enabled() -> bool:
    return bool(os.environ.get("LOG_TEST_TIMINGS"))


# ---------------------------------------------------------------------------
# Outbound: SuperTokens Querier (test server -> core)
# ---------------------------------------------------------------------------


def install_querier_timing() -> None:
    """Monkey-patch Querier's four HTTP entry points to log per-call timing.

    Safe to call multiple times; only patches once.
    """
    if not _enabled():
        return

    from supertokens_python.querier import Querier

    if getattr(Querier, "_timing_installed", False):
        return

    methods = [
        ("send_post_request", "POST"),
        ("send_get_request", "GET"),
        ("send_put_request", "PUT"),
        ("send_delete_request", "DELETE"),
    ]

    for attr, label in methods:
        original = getattr(Querier, attr)
        setattr(Querier, attr, _wrap_querier_method(original, label))

    Querier._timing_installed = True  # type: ignore[attr-defined]


def _wrap_querier_method(orig: Callable[..., Any], label: str) -> Callable[..., Any]:
    async def wrapper(self: Any, path: Any, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter_ns()
        try:
            return await orig(self, path, *args, **kwargs)
        finally:
            elapsed_ms = (time.perf_counter_ns() - start) / 1e6
            path_str = (
                path.get_as_string_dangerous()
                if hasattr(path, "get_as_string_dangerous")
                else str(path)
            )
            print(
                f"[QUERIER] {label} {path_str} {elapsed_ms:.1f}ms",
                flush=True,
            )

    return wrapper


# ---------------------------------------------------------------------------
# Inbound: HTTP requests served by the test server (browser -> test server)
# ---------------------------------------------------------------------------


def install_fastapi_request_timing(app: Any) -> None:
    """Add a FastAPI HTTP middleware that logs (method, path, status, ms)."""
    if not _enabled():
        return

    @app.middleware("http")
    async def _timing_middleware(  # pyright: ignore[reportUnusedFunction]
        request: Any, call_next: Callable[..., Any]
    ) -> Any:
        start = time.perf_counter_ns()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter_ns() - start) / 1e6
        print(
            f"[REQUEST] {request.method} {request.url.path} "
            f"{response.status_code} {elapsed_ms:.1f}ms",
            flush=True,
        )
        return response


def install_flask_request_timing(app: Any) -> None:
    """Add Flask before/after request hooks that log timing."""
    if not _enabled():
        return

    from flask import g, request

    @app.before_request
    def _start_timer() -> None:  # pyright: ignore[reportUnusedFunction]
        g._timing_start_ns = time.perf_counter_ns()

    @app.after_request
    def _log_timing(response: Any) -> Any:  # pyright: ignore[reportUnusedFunction]
        start_ns = getattr(g, "_timing_start_ns", time.perf_counter_ns())
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1e6
        print(
            f"[REQUEST] {request.method} {request.path} "
            f"{response.status_code} {elapsed_ms:.1f}ms",
            flush=True,
        )
        return response


def get_django_request_timing_middleware() -> Any:
    """Return a Django middleware class. Add the dotted path to MIDDLEWARE.

    Usage in settings.py:

        MIDDLEWARE = [
            ...,
            'tests._test_timing.DjangoRequestTimingMiddleware',
        ]
    """
    return DjangoRequestTimingMiddleware


class DjangoRequestTimingMiddleware:
    """Django request-timing middleware. No-op unless LOG_TEST_TIMINGS is set."""

    def __init__(self, get_response: Callable[..., Any]):
        self.get_response = get_response
        self.enabled = _enabled()

    def __call__(self, request: Any) -> Any:
        if not self.enabled:
            return self.get_response(request)

        start = time.perf_counter_ns()
        response = self.get_response(request)
        elapsed_ms = (time.perf_counter_ns() - start) / 1e6
        print(
            f"[REQUEST] {request.method} {request.path} "
            f"{response.status_code} {elapsed_ms:.1f}ms",
            flush=True,
        )
        return response
