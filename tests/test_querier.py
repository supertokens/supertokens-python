"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from fastapi import FastAPI

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.process_state import ProcessState, AllowedProcessStates
from supertokens_python.querier import Querier
from supertokens_python import init
from supertokens_python.recipe import session, thirdpartyemailpassword

from .utils import (
    reset, setup_st, clean_st, start_st,
    API_VERSION_TEST_BASIC_RESULT
)
from pytest import mark


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@mark.asyncio
async def test_that_if_that_once_API_version_is_there_it_doesnt_need_to_query_again():
    start_st()
    app = FastAPI()
    init(app, {
        'supertokens': {
            'connection_uri': "https://try.supertokens.io",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://localhost:9000",
            'website_domain': "http://localhost:8888",
            'api_base_path': "/auth"
        },
        'recipe_list': [thirdpartyemailpassword.init(), session.init()],
        'telemetry': False
    })

    querier = Querier.get_instance(None)

    assert await querier.get_api_version() in API_VERSION_TEST_BASIC_RESULT
    assert AllowedProcessStates.CALLING_SERVICE_IN_GET_API_VERSION in ProcessState.get_instance().history

    ProcessState.get_instance().reset()

    assert await querier.get_api_version() in API_VERSION_TEST_BASIC_RESULT
    assert AllowedProcessStates.CALLING_SERVICE_IN_GET_API_VERSION not in ProcessState.get_instance().history

# TODO: finish the test
# def test_that_rid_is_added_to_the_header_if_its_a_recipe_request():
#     start_st()
#     app = FastAPI()
#     init(app, {
#         'supertokens': {
#             'connection_uri': "https://try.supertokens.io",
#         },
#         'app_info': {
#             'app_name': "SuperTokens Demo",
#             'api_domain': "http://localhost:9000",
#             'website_domain': "http://localhost:8888",
#             'api_base_path': "/auth"
#         },
#         'recipe_list': [thirdpartyemailpassword.init(), session.init()],
#         'telemetry': False
#     })


@mark.asyncio
async def test_three_cores_one_dead_and_round_robin():
    start_st()
    start_st("localhost", 8082)
    start_st("localhost", 8081)
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567;http://localhost:8081/;http://localhost:8082",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://localhost:9000",
            'website_domain': "http://localhost:8888",
            'api_base_path': "/auth"
        },
        'recipe_list': [thirdpartyemailpassword.init(), session.init()],
        'telemetry': False
    })
    querier = Querier.get_instance(None)
    assert await querier.send_get_request(NormalisedURLPath(None, "/hello")) == "Hello\n"
    assert await querier.send_post_request(NormalisedURLPath(None, "/hello")) == "Hello\n"

    hostsAlive = querier.get_hosts_alive_for_testing()
    assert len(hostsAlive) == 2

    assert await querier.send_put_request(NormalisedURLPath(None, "/hello")) == "Hello\n"
    hostAlive = querier.get_hosts_alive_for_testing()
    assert "http://localhost:3567" in hostAlive
    assert "http://localhost:8081" not in hostAlive
    assert "http://localhost:8082" in hostAlive

# TODO: in the node sdk connection_uri is not set and the exception is set
# accordingly. In the fast api sdk


@mark.asyncio
async def test_that_no_connectionURI_given_but_recipe_used_throws_an_error():
    start_st()
    app = FastAPI()
    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [session.init()],
    })

    try:
        await session.get_session_data("")
        assert False
    except Exception as e:
        assert str(e) == 'Session does not exist.'


# TODO: finish the test
@mark.asyncio
async def test_that_no_connectionURI_given_recipe_override_and_used_doesnt_thrown_an_error():
    start_st()
    app = FastAPI()
    init(app, {
        'app_info': {
            'app_name': "SuperTokens",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [session.init(
            {
                "antiCsrf": "VIA_TOKEN"
            }
        )]
    })
