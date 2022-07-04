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
from typing import List
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.asyncio import (
    get_all_session_handles_for_user,
    get_session_information,
    update_access_token_payload,
    update_session_data,
    regenerate_access_token,
)
from supertokens_python.recipe.session.recipe_implementation import RecipeImplementation
from supertokens_python.recipe.session.session_functions import (
    create_new_session,
    get_session,
    refresh_session,
    revoke_session,
)

from tests.utils import clean_st, reset, setup_st, start_st


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@mark.asyncio
async def test_that_once_the_info_is_loaded_it_doesnt_query_again():
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

    response = await create_new_session(s.recipe_implementation, "", {}, {})

    assert response["session"] is not None
    assert response["accessToken"] is not None
    assert response["refreshToken"] is not None
    assert response["idRefreshToken"] is not None
    assert response["antiCsrfToken"] is not None
    assert len(response.keys()) == 5

    await get_session(
        s.recipe_implementation,
        response["accessToken"]["token"],
        response["antiCsrfToken"],
        True,
        response["idRefreshToken"]["token"],
    )
    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        not in ProcessState.get_instance().history
    )

    response2 = await refresh_session(
        s.recipe_implementation,
        response["refreshToken"]["token"],
        response["antiCsrfToken"],
        True,
    )

    assert response2["session"] is not None
    assert response2["accessToken"] is not None
    assert response2["refreshToken"] is not None
    assert response2["idRefreshToken"] is not None
    assert response2["antiCsrfToken"] is not None
    assert len(response.keys()) == 5

    response3 = await get_session(
        s.recipe_implementation,
        response2["accessToken"]["token"],
        response2["antiCsrfToken"],
        True,
        response["idRefreshToken"]["token"],
    )

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        in ProcessState.get_instance().history
    )

    assert response3["session"] is not None
    assert response3["accessToken"] is not None
    assert len(response3.keys()) == 2

    ProcessState.get_instance().reset()

    response4 = await get_session(
        s.recipe_implementation,
        response3["accessToken"]["token"],
        response2["antiCsrfToken"],
        True,
        response["idRefreshToken"]["token"],
    )
    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
        not in ProcessState.get_instance().history
    )

    assert response4["session"] is not None
    assert "accessToken" not in response4
    assert len(response4.keys()) == 1

    response5 = await revoke_session(
        s.recipe_implementation, response4["session"]["handle"]
    )

    assert response5 is True


@mark.asyncio
async def test_creating_many_sessions_for_one_user_and_looping():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init()],
    )
    start_st()

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, RecipeImplementation):
        raise Exception("Should never come here")

    access_tokens: List[str] = []
    for _ in range(7):
        new_session = await create_new_session(
            s.recipe_implementation, "someUser", {"someKey": "someValue"}, {}
        )
        access_tokens.append(new_session["accessToken"]["token"])

    session_handles = await get_all_session_handles_for_user("someUser")

    assert len(session_handles) == 7

    for i, handle in enumerate(session_handles):
        info = await get_session_information(handle)
        assert info is not None
        assert info.user_id == "someUser"
        assert info.access_token_payload["someKey"] == "someValue"

        is_updated = await update_access_token_payload(
            handle, {"someKey2": "someValue"}
        )
        assert is_updated

        is_updated = await update_session_data(handle, {"foo": "bar"})
        assert is_updated

    # Confirm that update funcs worked:
    for handle in session_handles:
        info = await get_session_information(handle)
        assert info is not None
        assert info.user_id == "someUser"
        assert info.access_token_payload == {"someKey2": "someValue"}
        assert info.session_data == {"foo": "bar"}

    # Regenerate access token with new access_token_payload
    for i, token in enumerate(access_tokens):
        result = await regenerate_access_token(token, {"bar": "baz"})
        assert result is not None
        assert (
            result.session.handle == session_handles[i]
        )  # Session handle should remain the same

        # Confirm that update worked:
        info = await get_session_information(result.session.handle)
        assert info is not None
        assert info.access_token_payload == {"bar": "baz"}

    # Try updating invalid handles:
    is_updated = await update_access_token_payload("invalidHandle", {"foo": "bar"})
    assert is_updated is False
    is_updated = await update_session_data("invalidHandle", {"foo": "bar"})
    assert is_updated is False
