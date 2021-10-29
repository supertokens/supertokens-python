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

from supertokens_python import init
from supertokens_python.process_state import ProcessState
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionRecipe
from tests.utils import (
    reset, setup_st, clean_st, start_st
)


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@mark.asyncio
async def test_that_once_the_info_is_loaded_it_doesnt_query_again():
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [session.init()
                        ],
    })
    start_st()

    session_recipe_instance = SessionRecipe.get_instance()
    await session_recipe_instance.recipe_implementation.get_handshake_info()

    assert not ProcessState.get_instance().get_service_called()

    ProcessState.get_instance().reset()

    assert ProcessState.get_instance().get_service_called()
