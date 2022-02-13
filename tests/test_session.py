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

from supertokens_python.recipe.session.recipe_implementation import \
    RecipeImplementation
from pytest import mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.session_functions import (
    create_new_session, get_session, refresh_session, revoke_session)

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
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name='SuperTokens Demo',
            api_domain='https://api.supertokens.io',
            website_domain='supertokens.io'
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        )]
    )
    start_st()

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, RecipeImplementation):
        raise Exception("Should never come here")

    response = await create_new_session(s.recipe_implementation, "", {}, {})

    assert response['session'] is not None
    assert response['accessToken'] is not None
    assert response['refreshToken'] is not None
    assert response['idRefreshToken'] is not None
    assert response['antiCsrfToken'] is not None
    assert len(response.keys()) == 5

    await get_session(s.recipe_implementation, response['accessToken']['token'], response['antiCsrfToken'], True, response['idRefreshToken']['token'])
    assert AllowedProcessStates.CALLING_SERVICE_IN_VERIFY not in ProcessState.get_instance().history

    response2 = await refresh_session(s.recipe_implementation, response['refreshToken']['token'], response['antiCsrfToken'], True)

    assert response2['session'] is not None
    assert response2['accessToken'] is not None
    assert response2['refreshToken'] is not None
    assert response2['idRefreshToken'] is not None
    assert response2['antiCsrfToken'] is not None
    assert len(response.keys()) == 5

    response3 = await get_session(s.recipe_implementation, response2['accessToken']['token'], response2['antiCsrfToken'], True, response['idRefreshToken']['token'])

    assert AllowedProcessStates.CALLING_SERVICE_IN_VERIFY in ProcessState.get_instance().history

    assert response3['session'] is not None
    assert response3['accessToken'] is not None
    assert len(response3.keys()) == 2

    ProcessState.get_instance().reset()

    response4 = await get_session(s.recipe_implementation, response3['accessToken']['token'], response2['antiCsrfToken'], True, response['idRefreshToken']['token'])
    assert AllowedProcessStates.CALLING_SERVICE_IN_VERIFY not in ProcessState.get_instance().history

    assert response4['session'] is not None
    assert 'accessToken' not in response4
    assert len(response4.keys()) == 1

    response5 = await revoke_session(s.recipe_implementation, response4['session']['handle'])

    assert response5 is True
