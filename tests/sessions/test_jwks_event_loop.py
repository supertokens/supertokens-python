import asyncio
import time
from typing import Any, List

import pytest
import requests
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


async def create_access_token() -> str:
    init(**get_st_init_args(url=get_new_core_app_url(), recipe_list=[session.init()]))  # type: ignore
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
