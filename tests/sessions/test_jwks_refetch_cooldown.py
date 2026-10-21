import json
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

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
from supertokens_python.recipe.session.jwks import (
    get_latest_keys,
    reset_jwks_cache,
)
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.types import RecipeUserId
from supertokens_python.utils import get_timestamp_ms, utf_base64encode

from tests.utils import get_new_core_app_url, get_st_init_args

REFETCH_COOLDOWN_SEC = 0.5


@pytest.fixture(autouse=True)
def clear_jwks_cache():
    reset_jwks_cache()
    yield
    reset_jwks_cache()


class JWKSFetchCounter:
    def __init__(
        self,
        mocker: MockerFixture,
        before_fetch: Optional[Callable[[], None]] = None,
    ):
        self.count = 0
        self._lock = threading.Lock()
        original_get = requests.get

        def get(url: Any, *args: Any, **kwargs: Any):
            if "jwks.json" in str(url):
                with self._lock:
                    self.count += 1
                if before_fetch is not None:
                    before_fetch()
            return original_get(url, *args, **kwargs)

        mocker.patch.object(requests, "get", side_effect=get)


def with_unknown_kid(access_token: str) -> str:
    _, payload, signature = access_token.split(".")
    header = utf_base64encode(
        json.dumps(
            {
                "kid": f"d-{uuid.uuid4()}",
                "typ": "JWT",
                "version": "5",
                "alg": "RS256",
            }
        ),
        urlsafe=True,
    ).rstrip("=")
    return ".".join([header, payload, signature])


async def init_and_get_verified_access_token() -> str:
    init(**get_st_init_args(url=get_new_core_app_url(), recipe_list=[session.init()]))  # type: ignore
    s = await create_new_session_without_request_response(
        "public", RecipeUserId("user-id"), {}, {}, True
    )
    access_token = s.get_access_token()
    # loads the keys into the cache
    assert await get_session_without_request_response(access_token) is not None
    return access_token


async def test_many_unknown_kid_tokens_cause_at_most_one_jwks_fetch(
    mocker: MockerFixture,
):
    access_token = await init_and_get_verified_access_token()
    time.sleep(REFETCH_COOLDOWN_SEC + 0.1)

    counter = JWKSFetchCounter(mocker)
    # Freeze the clock the JWKS cache uses, so all the lookups fall in one cooldown window
    # however long they take
    mocker.patch(
        "supertokens_python.recipe.session.jwks.get_timestamp_ms",
        return_value=get_timestamp_ms(),
    )
    for _ in range(50):
        with pytest.raises(TryRefreshTokenError):
            await get_session_without_request_response(with_unknown_kid(access_token))

    assert counter.count == 1


async def test_known_kid_tokens_are_verified_after_an_unknown_kid_token(
    mocker: MockerFixture,
):
    access_token = await init_and_get_verified_access_token()
    time.sleep(REFETCH_COOLDOWN_SEC + 0.1)

    counter = JWKSFetchCounter(mocker)
    with pytest.raises(TryRefreshTokenError):
        await get_session_without_request_response(with_unknown_kid(access_token))

    s = await get_session_without_request_response(access_token)
    assert s is not None
    assert s.get_user_id() == "user-id"
    assert counter.count == 1


async def test_unknown_kid_triggers_a_jwks_fetch_again_after_the_cooldown(
    mocker: MockerFixture,
):
    access_token = await init_and_get_verified_access_token()
    time.sleep(REFETCH_COOLDOWN_SEC + 0.1)

    counter = JWKSFetchCounter(mocker)
    with pytest.raises(TryRefreshTokenError):
        await get_session_without_request_response(with_unknown_kid(access_token))
    with pytest.raises(TryRefreshTokenError):
        await get_session_without_request_response(with_unknown_kid(access_token))
    assert counter.count == 1

    time.sleep(REFETCH_COOLDOWN_SEC + 0.1)

    with pytest.raises(TryRefreshTokenError):
        await get_session_without_request_response(with_unknown_kid(access_token))
    assert counter.count == 2


async def test_concurrent_unknown_kid_lookups_cause_at_most_one_jwks_fetch(
    mocker: MockerFixture,
):
    await init_and_get_verified_access_token()
    time.sleep(REFETCH_COOLDOWN_SEC + 0.1)
    config = SessionRecipe.get_instance().config

    counter = JWKSFetchCounter(mocker)
    thread_count = 50
    barrier = threading.Barrier(thread_count)
    errors: List[Optional[Exception]] = [None] * thread_count

    def lookup(i: int):
        barrier.wait()
        try:
            get_latest_keys(config, f"d-{uuid.uuid4()}")
        except Exception as e:
            errors[i] = e

    threads = [threading.Thread(target=lookup, args=(i,)) for i in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert all(e is not None for e in errors)
    assert counter.count == 1


async def test_cached_keys_can_be_read_while_jwks_are_being_fetched(
    mocker: MockerFixture,
):
    await init_and_get_verified_access_token()
    time.sleep(REFETCH_COOLDOWN_SEC + 0.1)
    config = SessionRecipe.get_instance().config
    known_kid = get_latest_keys(config)[0].key_id  # type: ignore

    fetch_started = threading.Event()
    release_fetch = threading.Event()

    def block_fetch():
        fetch_started.set()
        release_fetch.wait(timeout=10)

    JWKSFetchCounter(mocker, before_fetch=block_fetch)

    fetching_thread = threading.Thread(
        target=lambda: pytest.raises(
            Exception, get_latest_keys, config, f"d-{uuid.uuid4()}"
        )
    )
    fetching_thread.start()
    try:
        assert fetch_started.wait(timeout=5)

        result: Dict[str, Any] = {}

        def read_known_kid():
            result["keys"] = get_latest_keys(config, known_kid)

        reading_thread = threading.Thread(target=read_known_kid)
        reading_thread.start()
        reading_thread.join(timeout=2)

        assert not reading_thread.is_alive()
        assert [k.key_id for k in result["keys"]] == [known_kid]  # type: ignore
    finally:
        release_fetch.set()
        fetching_thread.join(timeout=10)


def test_session_recipe_reset_clears_the_jwks_cache_and_the_refetch_time():
    from supertokens_python.recipe.session import jwks

    jwks.cached_keys = jwks.CachedKeys([], 60)
    jwks.last_fetch_time_ms = get_timestamp_ms()

    SessionRecipe.reset()

    assert jwks.cached_keys is None
    assert jwks.last_fetch_time_ms is None
