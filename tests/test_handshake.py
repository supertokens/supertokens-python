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

from supertokens_python.recipe.session.recipe_implementation import RecipeImplementation
from pytest import mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionRecipe

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
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )
    start_st()

    session_recipe_instance = SessionRecipe.get_instance()
    if not isinstance(
        session_recipe_instance.recipe_implementation, RecipeImplementation
    ):
        raise Exception("Should never come here")
    await session_recipe_instance.recipe_implementation.get_handshake_info()

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_GET_HANDSHAKE_INFO
        in ProcessState.get_instance().history
    )

    ProcessState.get_instance().reset()
    await session_recipe_instance.recipe_implementation.get_handshake_info()

    assert (
        AllowedProcessStates.CALLING_SERVICE_IN_GET_HANDSHAKE_INFO
        not in ProcessState.get_instance().history
    )
