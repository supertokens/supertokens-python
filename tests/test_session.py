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

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

from fastapi import FastAPI, Depends
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from pytest import fixture, mark
from tests.testclient import TestClientWithNoCookieJar as TestClient
from requests.cookies import cookiejar_from_dict  # type: ignore

from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework import BaseRequest
from supertokens_python.framework.fastapi.fastapi_middleware import get_middleware
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.recipe import session
from supertokens_python.recipe.session import InputOverrideConfig, SessionRecipe
from supertokens_python.recipe.session.asyncio import (
    create_new_session as async_create_new_session,
)
from supertokens_python.recipe.session.asyncio import (
    get_all_session_handles_for_user,
    get_session_information,
)
from supertokens_python.recipe.session.asyncio import (
    revoke_session as asyncio_revoke_session,
)
from supertokens_python.recipe.session.asyncio import (
    merge_into_access_token_payload,
    update_session_data_in_database,
)
from supertokens_python.recipe.session.interfaces import (
    RecipeInterface,
    SessionContainer,
)
from supertokens_python.recipe.session.jwt import (
    parse_jwt_without_signature_verification,
)
from supertokens_python.recipe.session.recipe_implementation import RecipeImplementation
from supertokens_python.recipe.session.session_functions import (
    create_new_session,
    get_session,
    refresh_session,
    revoke_session,
)
from supertokens_python.recipe.session.framework.fastapi import verify_session
from tests.utils import (
    TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
    clean_st,
    reset,
    set_key_value_in_config,
    setup_st,
    start_st,
)

pytestmark = mark.asyncio


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


async def test_that_once_the_info_is_loaded_it_doesnt_query_again():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ],
    )
    start_st()

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, RecipeImplementation):
        raise Exception("Should never come here")

    response = await create_new_session(
        s.recipe_implementation, "public", "", False, {}, {}, None
    )

    assert response.session is not None
    assert response.accessToken is not None
    assert response.refreshToken is not None
    assert response.antiCsrfToken is not None

    access_token = parse_jwt_without_signature_verification(response.accessToken.token)

    await get_session(
        s.recipe_implementation, access_token, response.antiCsrfToken, True, False, None
    )
    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        not in ProcessState.get_instance().history
    )

    response2 = await refresh_session(
        s.recipe_implementation,
        response.refreshToken.token,
        response.antiCsrfToken,
        False,
        True,
        None,
    )

    assert response2.session is not None
    assert response2.accessToken is not None
    assert response2.refreshToken is not None
    assert response2.antiCsrfToken is not None

    access_token2 = parse_jwt_without_signature_verification(
        response2.accessToken.token
    )

    response3 = await get_session(
        s.recipe_implementation,
        access_token2,
        response2.antiCsrfToken,
        True,
        False,
        None,
    )

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        in ProcessState.get_instance().history
    )

    assert response3.session is not None
    assert response3.accessToken is not None

    ProcessState.get_instance().reset()

    access_token3 = parse_jwt_without_signature_verification(
        response3.accessToken.token
    )

    response4 = await get_session(
        s.recipe_implementation,
        access_token3,
        response2.antiCsrfToken,
        True,
        False,
        None,
    )
    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        not in ProcessState.get_instance().history
    )

    assert response4.session is not None
    assert response4.accessToken is None

    response5 = await revoke_session(
        s.recipe_implementation, response4.session.handle, {}
    )

    assert response5 is True


async def test_creating_many_sessions_for_one_user_and_looping():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )
    start_st()

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, RecipeImplementation):
        raise Exception("Should never come here")

    access_tokens: List[str] = []
    for _ in range(7):
        new_session = await create_new_session(
            s.recipe_implementation,
            "public",
            "someUser",
            False,
            {"someKey": "someValue"},
            {},
            None,
        )
        access_tokens.append(new_session.accessToken.token)

    session_handles = await get_all_session_handles_for_user("someUser", "public")

    assert len(session_handles) == 7

    for handle in session_handles:
        info = await get_session_information(handle)
        assert info is not None
        assert info.user_id == "someUser"
        assert info.custom_claims_in_access_token_payload["someKey"] == "someValue"

        is_updated = await merge_into_access_token_payload(
            handle, {"someKey": None, "someKey2": "someValue"}
        )
        assert is_updated

        is_updated = await update_session_data_in_database(handle, {"foo": "bar"})
        assert is_updated

    # Confirm that update funcs worked:
    for handle in session_handles:
        info = await get_session_information(handle)
        assert info is not None
        assert info.user_id == "someUser"
        assert info.custom_claims_in_access_token_payload == {"someKey2": "someValue"}
        assert info.session_data_in_database == {"foo": "bar"}

    regenerated_session_handles: List[str] = []
    # Regenerate access token with new access_token_payload
    for token in access_tokens:
        result = await s.recipe_implementation.regenerate_access_token(
            token, {"bar": "baz"}, {}
        )
        assert result is not None
        regenerated_session_handles.append(result.session.handle)

        # Confirm that update worked:
        info = await get_session_information(result.session.handle)
        assert info is not None
        assert info.custom_claims_in_access_token_payload == {"bar": "baz"}

    # Session handle should remain the same session handle should remain the same
    # but order isn't guaranteed so we should sort them
    assert sorted(regenerated_session_handles) == sorted(session_handles)

    # Try updating invalid handles:
    is_updated = await merge_into_access_token_payload("invalidHandle", {"foo": "bar"})
    assert is_updated is False
    is_updated = await update_session_data_in_database("invalidHandle", {"foo": "bar"})
    assert is_updated is False


@fixture(scope="function")
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    @app.get("/")
    async def home(_request: Request):  # type: ignore
        return {"hello": "world"}

    @app.post("/create")
    async def create_api(request: Request):  # type: ignore
        await async_create_new_session(request, "public", "test-user", {}, {})
        return ""

    @app.post("/sessioninfo-optional")
    async def _session_info(s: Optional[SessionContainer] = Depends(verify_session(session_required=False))):  # type: ignore
        if s is not None:
            return JSONResponse({"session": s.get_handle(), "user_id": s.get_user_id()})
        return JSONResponse({"message": "no session"})

    return TestClient(app)


async def test_signout_api_works_even_if_session_is_deleted_after_creation(
    driver_config_client: TestClient,
):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init(anti_csrf="VIA_TOKEN")],
    )
    start_st()

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, RecipeImplementation):
        raise Exception("Should never come here")
    user_id = "user_id"

    response = await create_new_session(
        s.recipe_implementation, "public", user_id, False, {}, {}, None
    )

    session_handle = response.session.handle

    revoked = await asyncio_revoke_session(session_handle)
    assert revoked

    signout_response = driver_config_client.post(
        url="/auth/signout",
        cookies={
            "sAccessToken": response.accessToken.token,
        },
        headers={"anti-csrf": response.antiCsrfToken or ""},
    )

    assert signout_response.json() == {"status": "OK"}

    assert (
        signout_response.headers["set-cookie"]
        == """sAccessToken=""; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; SameSite=lax; Secure, sRefreshToken=""; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/auth/session/refresh; SameSite=lax; Secure"""
    )


async def test_signout_api_returns_401_without_session_tokens(
    driver_config_client: TestClient,
):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init(anti_csrf="VIA_TOKEN")],
    )
    start_st()

    signout_response = driver_config_client.post(
        url="/auth/signout",
    )

    assert signout_response.status_code == 401


async def test_should_use_override_functions_in_session_container_methods():
    def override_session_functions(oi: RecipeInterface) -> RecipeInterface:
        oi_get_session_information = oi.get_session_information

        async def get_session_information(
            session_handle: str, user_context: Dict[str, Any]
        ):
            info = await oi_get_session_information(session_handle, user_context)
            assert info is not None
            info.session_data_in_database["foo"] = "bar"
            return info

        oi.get_session_information = get_session_information

        return oi

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                override=InputOverrideConfig(
                    functions=override_session_functions,
                ),
            )
        ],
    )
    start_st()

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, RecipeImplementation):
        raise Exception("Should never come here")

    mock_response = MagicMock()

    my_session = await async_create_new_session(mock_response, "public", "test_id")
    data = await my_session.get_session_data_from_database()

    assert data == {"foo": "bar"}


from supertokens_python.recipe.session.exceptions import raise_unauthorised_exception
from supertokens_python.recipe.session.interfaces import APIInterface, APIOptions
from tests.utils import (
    assert_info_clears_tokens,
    extract_all_cookies,
    extract_info,
    get_st_init_args,
)


async def test_revoking_session_during_refresh_with_revoke_session_with_200(
    driver_config_client: TestClient,
):
    def session_api_override(oi: APIInterface) -> APIInterface:
        oi_refresh_post = oi.refresh_post

        async def refresh_post(api_options: APIOptions, user_context: Dict[str, Any]):
            s = await oi_refresh_post(api_options, user_context)
            await s.revoke_session()
            return s

        oi.refresh_post = refresh_post
        return oi

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
                override=session.InputOverrideConfig(apis=session_api_override),
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
        },
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 200
    info = extract_info(response)
    assert_info_clears_tokens(info, "cookie")


async def test_revoking_session_during_refresh_with_revoke_session_sending_401(
    driver_config_client: TestClient,
):
    def session_api_override(oi: APIInterface) -> APIInterface:
        oi_refresh_post = oi.refresh_post

        async def refresh_post(api_options: APIOptions, user_context: Dict[str, Any]):
            s = await oi_refresh_post(api_options, user_context)
            await s.revoke_session()
            api_options.response.set_status_code(401)  # type: ignore
            api_options.response.set_json_content({})  # type: ignore
            return s

        oi.refresh_post = refresh_post
        return oi

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
                override=session.InputOverrideConfig(apis=session_api_override),
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200

    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
        },
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 401
    info = extract_info(response)
    assert_info_clears_tokens(info, "cookie")


async def test_revoking_session_during_refresh_and_throw_unauthorized(
    driver_config_client: TestClient,
):
    def session_api_override(oi: APIInterface) -> APIInterface:
        oi_refresh_post = oi.refresh_post

        async def refresh_post(api_options: APIOptions, user_context: Dict[str, Any]):
            await oi_refresh_post(api_options, user_context)
            return raise_unauthorised_exception("unauthorized", clear_tokens=True)

        oi.refresh_post = refresh_post
        return oi

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
                override=session.InputOverrideConfig(apis=session_api_override),
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200

    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
        },
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 401
    cookies = extract_all_cookies(response)

    assert (
        "anti-csrf" not in response.headers
    )  # TODO: This makes sense. But verify this
    assert response.headers["front-token"] != ""

    assert cookies["sAccessToken"]["value"] == ""
    assert cookies["sRefreshToken"]["value"] == ""
    assert cookies["sAccessToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
    assert cookies["sRefreshToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"

    assert cookies["sAccessToken"]["domain"] == ""
    assert cookies["sRefreshToken"]["domain"] == ""


async def test_revoking_session_during_refresh_fails_if_just_sending_401(
    driver_config_client: TestClient,
):
    def session_api_override(oi: APIInterface) -> APIInterface:
        oi_refresh_post = oi.refresh_post

        async def refresh_post(api_options: APIOptions, user_context: Dict[str, Any]):
            s = await oi_refresh_post(api_options, user_context)
            api_options.response.set_status_code(401)  # type: ignore
            api_options.response.set_json_content({})  # type: ignore
            return s

        oi.refresh_post = refresh_post
        return oi

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
                override=session.InputOverrideConfig(apis=session_api_override),
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200

    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
        },
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 401
    cookies = extract_all_cookies(response)

    assert response.headers["anti-csrf"] != ""
    assert response.headers["front-token"] != ""

    assert cookies["sAccessToken"]["value"] != ""
    assert cookies["sRefreshToken"]["value"] != ""


async def test_token_cookie_expires(
    driver_config_client: TestClient,
):
    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200

    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    for c in response.cookies:
        if c.name == "sAccessToken":  # 100 years (set by the SDK)
            # some time must have elasped since the cookie was set. So less than current time
            assert (
                datetime.fromtimestamp(c.expires or 0) - timedelta(days=365.25 * 100)
                < datetime.now()
            )
        if c.name == "sRefreshToken":  # 100 days (set by the core)
            assert (
                datetime.fromtimestamp(c.expires or 0) - timedelta(days=100)
                < datetime.now()
            )

    assert response.headers["anti-csrf"] != ""
    assert response.headers["front-token"] != ""

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
        },
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 200
    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    for c in response.cookies:
        if c.name == "sAccessToken":  # 100 years (set by the SDK)
            # some time must have elasped since the cookie was set. So less than current time
            assert (
                datetime.fromtimestamp(c.expires or 0) - timedelta(days=365.25 * 100)
                < datetime.now()
            )
        if c.name == "sRefreshToken":  # 100 days (set by the core)
            assert (
                datetime.fromtimestamp(c.expires or 0) - timedelta(days=100)
                < datetime.now()
            )

    assert response.headers["anti-csrf"] != ""
    assert response.headers["front-token"] != ""


from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
    get_session_without_request_response,
    refresh_session_without_request_response,
)


async def test_that_verify_session_doesnt_always_call_core():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ],
    )
    start_st()

    # s = SessionRecipe.get_instance()
    # if not isinstance(s.recipe_implementation, RecipeImplementation):
    #     raise Exception("Should never come here")

    # response = await create_new_session(s.recipe_implementation, "", False, {}, {})

    session1 = await create_new_session_without_request_response("public", "user-id")

    assert session1 is not None
    assert session1.access_token != ""
    assert session1.front_token != ""
    assert session1.refresh_token is not None

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        not in ProcessState.get_instance().history
    )

    session2 = await get_session_without_request_response(
        session1.access_token, session1.anti_csrf_token
    )

    assert session2 is not None
    assert session2.access_token != ""
    assert session2.front_token != ""
    assert session2.refresh_token is None

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        not in ProcessState.get_instance().history
    )

    session3 = await refresh_session_without_request_response(
        session1.refresh_token.token, False, session1.anti_csrf_token
    )

    assert session3 is not None
    assert session3.access_token != ""
    assert session3.front_token != ""
    assert session3.refresh_token is not None

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        not in ProcessState.get_instance().history
    )

    session4 = await get_session_without_request_response(
        session3.access_token, session3.anti_csrf_token
    )

    assert session4 is not None
    assert session4.access_token != ""
    assert session4.front_token != ""
    assert session4.refresh_token is None

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        in ProcessState.get_instance().history
    )  # Core got called this time


async def test_anti_csrf_header_via_custom_header_check_happens_only_when_access_token_is_provided(
    driver_config_client: TestClient,
):
    args = get_st_init_args([session.init(anti_csrf="VIA_CUSTOM_HEADER", get_token_transfer_method=lambda *_: "cookie")])  # type: ignore
    init(**args)  # type: ignore
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200

    cookies = extract_all_cookies(response)

    # With access token:
    # without RID:
    response = driver_config_client.post(
        "/sessioninfo-optional",
        cookies={
            "sAccessToken": cookies["sAccessToken"]["value"],
        },
    )
    assert response.status_code == 401
    assert response.json() == {"message": "try refresh token"}

    # with RID:
    response = driver_config_client.post(
        "/sessioninfo-optional",
        cookies={
            "sAccessToken": cookies["sAccessToken"]["value"],
        },
        headers={
            "rid": "session",
        },
    )
    assert response.status_code == 200
    assert list(response.json()) == ["session", "user_id"]

    # Clear access tokens:
    driver_config_client.cookies.clear()

    # Without access tokens:
    # without RID:
    response = driver_config_client.post("/sessioninfo-optional")
    assert response.status_code == 200
    assert response.json() == {"message": "no session"}

    # with RID:
    response = driver_config_client.post(
        "/sessioninfo-optional",
        headers={
            "rid": "session",
        },
    )
    assert response.status_code == 200
    assert response.json() == {"message": "no session"}


async def test_expose_access_token_to_frontend_in_cookie_based_auth(
    driver_config_client: TestClient,
):
    args = get_st_init_args([session.init(expose_access_token_to_frontend_in_cookie_based_auth=True, get_token_transfer_method=lambda *_: "cookie")])  # type: ignore
    init(**args)  # type: ignore
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200
    assert len(response.headers["st-access-token"]) > 0

    reset(stop_core=True)

    args = get_st_init_args([session.init(expose_access_token_to_frontend_in_cookie_based_auth=False, get_token_transfer_method=lambda *_: "cookie")])  # type: ignore
    init(**args)  # type: ignore
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200
    assert "st-access-token" not in response.headers


async def test_token_transfer_method_works_when_using_origin_function(
    driver_config_client: TestClient,
):
    def get_origin(req: Optional[BaseRequest], _: Dict[str, Any]) -> str:
        if req is not None:
            value = req.get_header("origin")
            if value is not None:
                return value
        return "localhost:3000"

    def token_transfer_method(req: BaseRequest, _: bool, __: Dict[str, Any]):
        if req.get_header("origin") == "localhost:3002":
            return "cookie"
        return "header"

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://localhost:8000",
            origin=get_origin,
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[session.init(get_token_transfer_method=token_transfer_method)],
    )
    start_st()

    response = driver_config_client.post("/create")
    assert response.status_code == 200
    assert len(response.headers["st-access-token"]) > 0
    assert len(response.headers["st-refresh-token"]) > 0
    assert len(response.headers.get("set-cookie", [])) == 0

    response = driver_config_client.post(
        "/create", headers={"origin": "localhost:3002"}
    )
    assert response.status_code == 200
    assert len(response.headers.get("st-access-token", [])) == 0
    assert len(response.headers.get("st-refresh-token", [])) == 0
    assert len(response.headers.get("set-cookie", [])) > 0


async def test_clear_all_session_tokens_if_refresh_called_without_refresh_token_but_with_access_token(
    driver_config_client: TestClient,
):
    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies={"sAccessToken ": cookies["sAccessToken"]["value"]},
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 401
    response_cookies = extract_all_cookies(response)
    assert response_cookies["sAccessToken"]["value"] == ""
    assert (
        response_cookies["sAccessToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
    )
    assert response_cookies["sRefreshToken"]["value"] == ""
    assert (
        response_cookies["sRefreshToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
    )


async def test_clear_all_session_tokens_if_refresh_called_without_refresh_token_but_with_an_expired_access_token(
    driver_config_client: TestClient,
):
    set_key_value_in_config(TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY, "1")

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    # Wait for the access token to expire
    await asyncio.sleep(2)

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies={"sAccessToken ": cookies["sAccessToken"]["value"]},
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 401
    response_cookies = extract_all_cookies(response)
    assert response_cookies["sAccessToken"]["value"] == ""
    assert (
        response_cookies["sAccessToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
    )
    assert response_cookies["sRefreshToken"]["value"] == ""
    assert (
        response_cookies["sRefreshToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
    )


async def test_access_and_refresh_tokens_are_cleared_if_multiple_tokens_are_passed_to_refresh_endpoint(
    driver_config_client: TestClient,
):

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
                older_cookie_domain="example.com",
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    cookiejar = cookiejar_from_dict({})  # type: ignore
    cookiejar.set("sAccessToken", cookies["sAccessToken"]["value"])  # type: ignore
    cookiejar.set("sRefreshToken", cookies["sRefreshToken"]["value"], path="/auth/session/refresh")  # type: ignore
    cookiejar.set("sAccessToken", cookies["sAccessToken"]["value"], domain="testserver.local")  # type: ignore
    cookiejar.set("sRefreshToken", cookies["sRefreshToken"]["value"], domain="testserver.local", path="/auth/session/refresh")  # type: ignore

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies=cookiejar,  # type: ignore
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )

    assert response.status_code == 200
    response_cookies = extract_all_cookies(response)

    assert response_cookies["sAccessToken"]["value"] == ""
    assert (
        response_cookies["sAccessToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
    )
    assert response_cookies["sAccessToken"]["domain"] == "example.com"
    assert response_cookies["sRefreshToken"]["value"] == ""
    assert (
        response_cookies["sRefreshToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
    )
    assert response_cookies["sRefreshToken"]["domain"] == "example.com"


async def test_refresh_endpoint_throws_500_if_multiple_tokens_are_passed_and_older_cookie_domain_is_not_set(
    driver_config_client: TestClient,
):

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    cookiejar = cookiejar_from_dict({})  # type: ignore
    cookiejar.set("sAccessToken", cookies["sAccessToken"]["value"])  # type: ignore
    cookiejar.set("sRefreshToken", cookies["sRefreshToken"]["value"], path="/auth/session/refresh")  # type: ignore
    cookiejar.set("sAccessToken", cookies["sAccessToken"]["value"], domain="testserver.local")  # type: ignore
    cookiejar.set("sRefreshToken", cookies["sRefreshToken"]["value"], domain="testserver.local", path="/auth/session/refresh")  # type: ignore

    try:
        response = driver_config_client.post(
            "/auth/session/refresh",
            cookies=cookiejar,  # type: ignore
            headers={"anti-csrf": response.headers["anti-csrf"]},
        )
    except Exception as e:
        assert (
            str(e)
            == "The request contains multiple session cookies. This may happen if you've changed the 'cookie_domain' setting in your configuration. To clear tokens from the previous domain, set 'older_cookie_domain' in your config."
        )


async def test_verify_session_returns_401_if_multiple_tokens_are_passed_in_the_request(
    driver_config_client: TestClient,
):

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    cookies = extract_all_cookies(response)

    assert "sAccessToken" in cookies
    assert "sRefreshToken" in cookies

    assert "anti-csrf" in response.headers
    assert "front-token" in response.headers

    cookiejar = cookiejar_from_dict({})  # type: ignore
    cookiejar.set("sAccessToken", cookies["sAccessToken"]["value"])  # type: ignore
    cookiejar.set("sRefreshToken", cookies["sRefreshToken"]["value"], path="/auth/session/refresh")  # type: ignore
    cookiejar.set("sAccessToken", cookies["sAccessToken"]["value"], domain="testserver.local")  # type: ignore
    cookiejar.set("sRefreshToken", cookies["sRefreshToken"]["value"], domain="testserver.local", path="/auth/session/refresh")  # type: ignore

    response = driver_config_client.post(
        "/sessioninfo-optional",
        cookies=cookiejar,  # type: ignore
        headers={"anti-csrf": response.headers["anti-csrf"]},
    )
    assert response.status_code == 401
    assert response.json() == {"message": "try refresh token"}


async def test_verify_session_returns_200_in_header_based_auth_even_if_multiple_tokens_are_present_in_cookie(
    driver_config_client: TestClient,
):

    init_args = get_st_init_args(
        [
            session.init(
                get_token_transfer_method=lambda _, __, ___: "header",
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    info = extract_info(response)

    assert "accessTokenFromHeader" in info
    assert "refreshTokenFromHeader" in info

    cookiejar = cookiejar_from_dict({})  # type: ignore
    cookiejar.set("sAccessToken", info["accessTokenFromHeader"])  # type: ignore
    cookiejar.set("sRefreshToken", info["refreshTokenFromHeader"], path="/auth/session/refresh")  # type: ignore
    cookiejar.set("sAccessToken", info["accessTokenFromHeader"], domain="testserver.local")  # type: ignore
    cookiejar.set("sRefreshToken", info["refreshTokenFromHeader"], domain="testserver.local", path="/auth/session/refresh")  # type: ignore

    response = driver_config_client.post(
        "/sessioninfo-optional",
        cookies=cookiejar,  # type: ignore
        headers={"Authorization": f"Bearer {info['accessTokenFromHeader']}"},
    )
    assert response.status_code == 200
    assert list(response.json()) == ["session", "user_id"]


async def test_refresh_endpoint_refreshes_the_token_in_header_based_auth_if_multiple_tokens_are_present_in_cookie(
    driver_config_client: TestClient,
):

    init_args = get_st_init_args(
        [
            session.init(
                get_token_transfer_method=lambda _, __, ___: "header",
            )
        ]
    )
    init(**init_args)
    start_st()

    response = driver_config_client.post("/create")
    info = extract_info(response)

    assert "accessTokenFromHeader" in info
    assert "refreshTokenFromHeader" in info

    cookiejar = cookiejar_from_dict({})  # type: ignore
    cookiejar.set("sAccessToken", info["accessTokenFromHeader"])  # type: ignore
    cookiejar.set("sRefreshToken", info["refreshTokenFromHeader"], path="/auth/session/refresh")  # type: ignore
    cookiejar.set("sAccessToken", info["accessTokenFromHeader"], domain="testserver.local")  # type: ignore
    cookiejar.set("sRefreshToken", info["refreshTokenFromHeader"], domain="testserver.local", path="/auth/session/refresh")  # type: ignore

    response = driver_config_client.post(
        "/auth/session/refresh",
        cookies=cookiejar,  # type: ignore
        headers={"Authorization": f"Bearer {info['refreshTokenFromHeader']}"},
    )
    assert response.status_code == 200
    response_info = extract_info(response)

    assert "accessTokenFromHeader" in response_info
    assert "refreshTokenFromHeader" in response_info
