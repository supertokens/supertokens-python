import asyncio
import time
from typing import Any

import pytest
import requests
from pytest_mock import MockerFixture
from supertokens_python import init
from supertokens_python.recipe import session
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


def delay_jwks_fetch(mocker: MockerFixture, fail: bool = False):
    original_get = requests.get

    def get(url: Any, *args: Any, **kwargs: Any):
        if "jwks.json" in str(url):
            time.sleep(JWKS_FETCH_DELAY_SEC)
            if fail:
                raise requests.ConnectionError("core unavailable")
        return original_get(url, *args, **kwargs)

    mocker.patch.object(requests, "get", side_effect=get)


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
