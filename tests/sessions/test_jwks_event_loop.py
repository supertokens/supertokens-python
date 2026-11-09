import asyncio
import gc
import json
import threading
import time
from types import SimpleNamespace
from typing import Any, List, Optional

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm
from pytest_mock import MockerFixture
from supertokens_python import init
from supertokens_python.recipe import session
from supertokens_python.recipe.session import jwks
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
    get_session_without_request_response,
)
from supertokens_python.recipe.session.exceptions import TryRefreshTokenError
from supertokens_python.recipe.session.jwks import reset_jwks_cache
from supertokens_python.types import RecipeUserId

from tests.utils import get_new_core_app_url, get_st_init_args

JWKS_FETCH_DELAY_SEC = 0.5


async def create_access_token(jwks_refresh_interval_sec: Optional[int] = None) -> str:
    init(
        **get_st_init_args(  # type: ignore
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(jwks_refresh_interval_sec=jwks_refresh_interval_sec)
            ],
        )
    )
    s = await create_new_session_without_request_response(
        "public", RecipeUserId("user-id"), {}, {}, True
    )
    return s.get_access_token()


def delay_jwks_fetch(mocker: MockerFixture, fail: bool = False) -> List[str]:
    """Delays (and optionally fails) every JWKS fetch. Returns the list of fetched JWKS urls."""
    original_get = requests.get
    jwks_fetches: List[str] = []

    def get(url: Any, *args: Any, **kwargs: Any):
        if "jwks.json" in str(url):
            jwks_fetches.append(str(url))
            time.sleep(JWKS_FETCH_DELAY_SEC)
            if fail:
                raise requests.ConnectionError("core unavailable")
        return original_get(url, *args, **kwargs)

    mocker.patch.object(requests, "get", side_effect=get)
    return jwks_fetches


async def longest_event_loop_stall_while(coro: Any) -> float:
    loop = asyncio.get_running_loop()
    ticks = [loop.time()]

    async def tick():
        while True:
            await asyncio.sleep(0.01)
            ticks.append(loop.time())

    ticker = asyncio.ensure_future(tick())
    try:
        await coro
    finally:
        ticker.cancel()
    ticks.append(loop.time())
    return max(later - earlier for earlier, later in zip(ticks, ticks[1:]))


async def test_fetching_jwks_does_not_block_the_event_loop(mocker: MockerFixture):
    access_token = await create_access_token()
    reset_jwks_cache()
    delay_jwks_fetch(mocker)

    started = time.monotonic()
    stall = await longest_event_loop_stall_while(
        get_session_without_request_response(access_token, check_database=False)
    )

    assert time.monotonic() - started >= JWKS_FETCH_DELAY_SEC
    assert stall < JWKS_FETCH_DELAY_SEC / 2


async def test_failing_jwks_fetch_does_not_block_the_event_loop(
    mocker: MockerFixture,
):
    access_token = await create_access_token()
    reset_jwks_cache()
    delay_jwks_fetch(mocker, fail=True)

    async def verify():
        with pytest.raises(TryRefreshTokenError):
            await get_session_without_request_response(
                access_token, check_database=False
            )

    stall = await longest_event_loop_stall_while(verify())

    assert stall < JWKS_FETCH_DELAY_SEC / 2


async def test_concurrent_jwks_cache_misses_share_one_fetch(mocker: MockerFixture):
    access_token = await create_access_token()
    reset_jwks_cache()
    jwks_fetches = delay_jwks_fetch(mocker)
    blocking_fetch = mocker.spy(jwks, "get_latest_keys")

    sessions = await asyncio.gather(
        *[
            get_session_without_request_response(access_token, check_database=False)
            for _ in range(20)
        ]
    )

    assert all(s is not None for s in sessions)
    # one job in the shared worker pool, not one per caller waiting for fetch_lock
    assert blocking_fetch.call_count == 1
    assert len(jwks_fetches) == 1


async def test_concurrent_jwks_cache_misses_share_a_failing_fetch(
    mocker: MockerFixture,
):
    access_token = await create_access_token()
    reset_jwks_cache()
    jwks_fetches = delay_jwks_fetch(mocker, fail=True)
    blocking_fetch = mocker.spy(jwks, "get_latest_keys")

    results = await asyncio.gather(
        *[
            get_session_without_request_response(access_token, check_database=False)
            for _ in range(20)
        ],
        return_exceptions=True,
    )

    assert all(isinstance(r, TryRefreshTokenError) for r in results)
    assert blocking_fetch.call_count == 1
    # one fetch per configured core url, not one per caller
    assert len(jwks_fetches) == len(set(jwks_fetches))


async def test_concurrent_callers_share_keys_the_cache_does_not_keep(
    mocker: MockerFixture,
):
    # With a refresh interval of 0 the cache is stale as soon as it is written, so callers that
    # joined the fetch must use the keys it returned instead of reading the cache.
    access_token = await create_access_token(jwks_refresh_interval_sec=0)
    reset_jwks_cache()
    delay_jwks_fetch(mocker)
    blocking_fetch = mocker.spy(jwks, "get_latest_keys")

    sessions = await asyncio.gather(
        *[
            get_session_without_request_response(access_token, check_database=False)
            for _ in range(20)
        ]
    )

    assert all(s is not None for s in sessions)
    assert blocking_fetch.call_count == 1


async def test_cancelled_callers_do_not_leave_an_unretrieved_fetch_error(
    mocker: MockerFixture,
):
    access_token = await create_access_token()
    reset_jwks_cache()
    delay_jwks_fetch(mocker, fail=True)
    loop = asyncio.get_running_loop()
    unhandled: List[Any] = []
    loop.set_exception_handler(lambda _, context: unhandled.append(context))

    callers = [
        asyncio.ensure_future(
            get_session_without_request_response(access_token, check_database=False)
        )
        for _ in range(5)
    ]
    await asyncio.sleep(JWKS_FETCH_DELAY_SEC / 5)
    for caller in callers:
        caller.cancel()
    await asyncio.gather(*callers, return_exceptions=True)

    fetch = jwks.pending_fetch
    assert fetch is not None
    await asyncio.wait([fetch])
    del fetch
    gc.collect()
    loop.set_exception_handler(None)

    assert unhandled == []
    assert jwks.pending_fetch is None


def make_jwk(kid: str) -> PyJWK:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256"})
    return PyJWK.from_dict(jwk)


async def test_caller_joining_a_failed_fetch_uses_its_key_from_the_cache(
    mocker: MockerFixture,
):
    # Caller A (unknown kid) starts the fetch and caller B (known kid) joins it. Before the
    # fetch runs, another thread refreshes the cache with B's key, so A's fetch fails on the
    # refetch cooldown. B must still get its key from the cache, as the sync API would.
    config = SimpleNamespace(jwks_refresh_interval_sec=60)
    known_key = make_jwk("known-kid")
    both_callers_waiting = threading.Event()

    def fetch_after_another_thread_refreshed_the_cache(*_: Any) -> List[PyJWK]:
        both_callers_waiting.wait(5)
        with jwks.RWLockContext(jwks.mutex, read=False):
            jwks.cached_keys = jwks.CachedKeys([known_key], 60)
            # refreshed just before this fetch started, so it is not shared as the fetch result
            jwks.cached_keys.last_refresh_time -= 1000
            jwks.last_fetch_time_ms = jwks.cached_keys.last_refresh_time
        raise Exception("No matching JWKS found")

    mocker.patch.object(
        jwks,
        "get_latest_keys",
        side_effect=fetch_after_another_thread_refreshed_the_cache,
    )

    caller_a = asyncio.ensure_future(
        jwks.get_latest_keys_async(config, "unknown-kid")  # type: ignore
    )
    await asyncio.sleep(0)
    caller_b = asyncio.ensure_future(
        jwks.get_latest_keys_async(config, "known-kid")  # type: ignore
    )
    await asyncio.sleep(0)
    both_callers_waiting.set()
    result_a, result_b = await asyncio.gather(
        caller_a, caller_b, return_exceptions=True
    )

    assert isinstance(result_a, Exception)
    assert result_b == [known_key]


def test_cache_miss_without_an_asyncio_loop_fetches_synchronously(
    mocker: MockerFixture,
):
    # Under a non-asyncio backend (for example trio) there is no running asyncio loop, so the
    # fetch cannot go to a worker thread. It must fall back to the sync fetch instead of failing.
    reset_jwks_cache()
    config = SimpleNamespace(jwks_refresh_interval_sec=60)
    known_key = make_jwk("known-kid")
    blocking_fetch = mocker.patch.object(
        jwks, "get_latest_keys", return_value=[known_key]
    )

    # Drive the coroutine by hand, the way a non-asyncio event loop would
    coro = jwks.get_latest_keys_async(config, "known-kid")  # type: ignore
    with pytest.raises(StopIteration) as finished:
        coro.send(None)

    assert finished.value.value == [known_key]
    blocking_fetch.assert_called_once_with(config, "known-kid")
