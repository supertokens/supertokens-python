# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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
from pytest import mark
from supertokens_python.recipe import (
    session,
    emailpassword,
    emailverification,
    dashboard,
    thirdparty,
)
from supertokens_python import InputAppInfo
from supertokens_python.recipe.emailpassword.asyncio import get_user_by_id, sign_up
from supertokens_python.recipe.thirdparty.asyncio import (
    get_user_by_id as tp_get_user_by_id,
)
import asyncio
import respx
import httpx
import json
from supertokens_python import init, SupertokensConfig
from supertokens_python.querier import Querier, NormalisedURLPath

from tests.utils import get_st_init_args
from tests.utils import (
    setup_function,
    teardown_function,
    start_st,
)
from typing import Any, Dict, Optional

_ = setup_function
_ = teardown_function

pytestmark = mark.asyncio
respx_mock = respx.MockRouter


async def test_network_call_is_retried_as_expected():
    # Test that network call is retried properly
    # Test that rate limiting errors are thrown back to the user
    args = get_st_init_args(
        [
            session.init(),
            emailpassword.init(),
            emailverification.init(mode="OPTIONAL"),
            dashboard.init(),
        ]
    )
    args["supertokens_config"] = SupertokensConfig("http://localhost:6789")
    init(**args)  # type: ignore
    start_st()

    Querier.api_version = "3.0"
    q = Querier.get_instance()

    api2_call_count = 0

    def api2_side_effect(_: httpx.Request):
        nonlocal api2_call_count
        api2_call_count += 1

        if api2_call_count == 3:
            return httpx.Response(200)

        return httpx.Response(429, json={})

    with respx_mock() as mocker:
        api1 = mocker.get("http://localhost:6789/api1").mock(
            httpx.Response(429, json={"status": "RATE_ERROR"})
        )
        api2 = mocker.get("http://localhost:6789/api2").mock(
            side_effect=api2_side_effect
        )
        api3 = mocker.get("http://localhost:6789/api3").mock(httpx.Response(200))

        try:
            await q.send_get_request(NormalisedURLPath("/api1"), None, None)
        except Exception as e:
            if "with status code: 429" in str(
                e
            ) and 'message: {"status": "RATE_ERROR"}' in str(e):
                pass
            else:
                raise e

        await q.send_get_request(NormalisedURLPath("/api2"), None, None)
        await q.send_get_request(NormalisedURLPath("/api3"), None, None)

        # 1 initial request + 5 retries
        assert api1.call_count == 6
        # 2 403 and 1 200
        assert api2.call_count == 3
        # 200 in the first attempt
        assert api3.call_count == 1


async def test_parallel_calls_have_independent_counters():
    args = get_st_init_args(
        [
            session.init(),
            emailpassword.init(),
            emailverification.init(mode="OPTIONAL"),
            dashboard.init(),
        ]
    )
    init(**args)  # type: ignore
    start_st()

    Querier.api_version = "3.0"
    q = Querier.get_instance()

    call_count1 = 0
    call_count2 = 0

    def api_side_effect(r: httpx.Request):
        nonlocal call_count1, call_count2

        id_ = int(r.url.params.get("id"))
        if id_ == 1:
            call_count1 += 1
        elif id_ == 2:
            call_count2 += 1

        return httpx.Response(429, json={})

    with respx_mock() as mocker:
        api = mocker.get("http://localhost:3567/api").mock(side_effect=api_side_effect)

        async def call_api(id_: int):
            try:
                await q.send_get_request(NormalisedURLPath("/api"), {"id": id_}, None)
            except Exception as e:
                if "with status code: 429" in str(e):
                    pass
                else:
                    raise e

        _ = await asyncio.gather(
            call_api(1),
            call_api(2),
        )

        # 1 initial request + 5 retries
        assert call_count1 == 6
        assert call_count2 == 6

        assert api.call_count == 12


async def test_querier_text_and_headers():
    args = get_st_init_args([session.init()])
    args["supertokens_config"] = SupertokensConfig("http://localhost:6789")
    init(**args)  # type: ignore
    start_st()

    Querier.api_version = "3.0"
    q = Querier.get_instance()

    with respx_mock() as mocker:
        text = "foo"
        mocker.get("http://localhost:6789/text-api").mock(
            httpx.Response(200, text=text, headers={"greet": "hello"})
        )

        res = await q.send_get_request(NormalisedURLPath("/text-api"), None, None)
        assert res == {
            "_text": "foo",
            "_headers": {
                "greet": "hello",
                "content-type": "text/plain; charset=utf-8",
                "content-length": str(len("foo")),
            },
        }

        body = {"bar": "baz"}
        mocker.get("http://localhost:6789/json-api").mock(
            httpx.Response(200, json=body, headers={"greet": "hi"})
        )

        res = await q.send_get_request(NormalisedURLPath("/json-api"), None, None)
        assert res == {
            "bar": "baz",
            "_headers": {
                "greet": "hi",
                "content-type": "application/json",
                "content-length": str(len(json.dumps(body))),
            },
        }


async def test_caching_works():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
            thirdparty.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {}
    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert not called_core

    user = await tp_get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    called_core = False

    user = await tp_get_user_by_id("random", user_context)
    assert user is None
    assert not called_core

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert not called_core


async def test_caching_gets_clear_with_non_get():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {}
    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    await sign_up("public", "test@example.com", "abcd1234", user_context)

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert not called_core


async def test_no_caching_if_disabled_by_user():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567",
            network_interceptor=intercept,
            disable_core_call_cache=True,
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {}
    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert called_core


async def test_no_caching_if_headers_are_different():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567",
            network_interceptor=intercept,
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
            thirdparty.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {}
    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert not called_core

    called_core = False

    user = await tp_get_user_by_id("random", user_context)
    assert user is None
    assert called_core


async def test_caching_gets_clear_when_query_without_user_context():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {}
    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    await sign_up("public", "test@example.com", "abcd1234")

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert called_core


async def test_caching_does_not_get_clear_with_non_get_if_keep_alive():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {"_default": {"keep_cache_alive": True}}
    user_context_2: Dict[str, Any] = {}

    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context_2)

    assert user is None
    assert called_core

    await sign_up("public", "test@example.com", "abcd1234", user_context)

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert not called_core

    user = await get_user_by_id("random", user_context_2)

    assert user is None
    assert not called_core


async def test_caching_gets_clear_with_non_get_if_keep_alive_is_false():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {"_default": {"keep_cache_alive": False}}
    user_context_2: Dict[str, Any] = {}

    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context_2)

    assert user is None
    assert called_core

    await sign_up("public", "test@example.com", "abcd1234", user_context)

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert not called_core

    user = await get_user_by_id("random", user_context_2)

    assert user is None
    assert called_core


async def test_caching_gets_clear_with_non_get_if_keep_alive_is_not_set():

    called_core = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal called_core
        called_core = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            connection_uri="http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            emailpassword.init(),
            dashboard.init(),
        ],
    )  # type: ignore
    start_st()
    user_context: Dict[str, Any] = {}
    user_context_2: Dict[str, Any] = {}

    user = await get_user_by_id("random", user_context)

    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context_2)

    assert user is None
    assert called_core

    await sign_up("public", "test@example.com", "abcd1234", user_context)

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert called_core

    called_core = False

    user = await get_user_by_id("random", user_context)
    assert user is None
    assert not called_core

    user = await get_user_by_id("random", user_context_2)

    assert user is None
    assert called_core
