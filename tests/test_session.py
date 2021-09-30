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

import respx
from fastapi import FastAPI
from pytest import mark

from supertokens_python import init
from supertokens_python.recipe import session
from supertokens_python.process_state import ProcessState, AllowedProcessStates
from supertokens_python.recipe.session import SessionRecipe, revoke_session, get_all_session_handles_for_user, \
    revoke_all_sessions_for_user
from supertokens_python.recipe.session.session_functions import create_new_session, refresh_session, get_session, \
    update_session_data, get_session_data, update_jwt_payload, get_jwt_payload
from .utils import (
    reset, setup_st, clean_st, start_st
)


def request_mock():
    mock = respx.mock(assert_all_mocked=False, assert_all_called=False)

    mock.route(host="localhost").pass_through()
    return mock


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()
#
# @mark.asyncio
# async def test_token_theft_detection_with_api_key():
#     set_key_value_in_config("api_keys", "shfo3h98308hOIHoei309saiho")
#     start_st()
#     app = FastAPI()
#     init(app, {
#         'supertokens': {
#             'connection_uri': "http://localhost:3567",
#             'api_key': "shfo3h98308hOIHoei309saiho",
#         },
#         'app_info': {
#             'app_name': "SuperTokens Demo",
#             'api_domain': "api.supertokens.io",
#             'website_domain': "supertokens.io",
#             'api_base_path': "/auth"
#         },
#         'recipe_list': [session.init(
#             {
#                 'anti_csrf': 'VIA_TOKEN'
#             }
#         )],
#     })
#
#     response = await create_new_session(recipe=SessionRecipe.get_instance(), user_id="", jwt_payload={},
#                                         session_data={})
#     response2 = await refresh_session(recipe=SessionRecipe.get_instance(),
#                                       refresh_token=response['refreshToken']['token'],
#                                       anti_csrf_token=response['antiCsrfToken'], contains_custom_header=False)
#     session_info = await get_session(recipe=SessionRecipe.get_instance(),
#                                      access_token=response2['accessToken']['token'],
#                                      anti_csrf_token=response2['antiCsrfToken'], do_anti_csrf_check=True,
#                                      contains_custom_header=True)
#
#     try:
#         await refresh_session(recipe=SessionRecipe.get_instance(), refresh_token=response['refreshToken']['token'],
#                               anti_csrf_token=response['antiCsrfToken'], contains_custom_header=False)
#         raise Exception("should not have come here")
#     except Exception as e:
#         assert e.__class__.__name__ == 'TokenTheftError'
#
#
# @mark.asyncio
# async def test_query_without_api_key():
#     set_key_value_in_config("api_keys", "shfo3h98308hOIHoei309saiho")
#     start_st()
#     app = FastAPI()
#
#     init(app, {
#         'supertokens': {
#             'connection_uri': "http://localhost:3567",
#         },
#         'app_info': {
#             'app_name': "SuperTokens Demo",
#             'api_domain': "api.supertokens.io",
#             'website_domain': "supertokens.io",
#             'api_base_path': "/auth"
#         },
#         'recipe_list': [session.init(
#             {
#                 'anti_csrf': 'VIA_TOKEN'
#             }
#         )],
#     })
#     try:
#         await Querier.get_instance(None).get_api_version()
#         raise Exception('should not have come here')
#     except Exception as e:
#         assert str(e) == "SuperTokens core threw an error for a GET request to path: /apiversion with status code: 401 and message: Invalid API key\n"
#


@mark.asyncio
async def test_token_theft_detection():
    start_st()
    app = FastAPI()
    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    response = await create_new_session(recipe=SessionRecipe.get_instance(), user_id="", jwt_payload={},
                                        session_data={})
    response2 = await refresh_session(recipe=SessionRecipe.get_instance(), refresh_token=response['refreshToken']['token'],
                                      anti_csrf_token=response['antiCsrfToken'], contains_custom_header=False)
    session_info = await get_session(recipe=SessionRecipe.get_instance(), access_token=response2['accessToken']['token'],
                                     anti_csrf_token=response2['antiCsrfToken'], do_anti_csrf_check=True, contains_custom_header=True)

    try:
        await refresh_session(recipe=SessionRecipe.get_instance(), refresh_token=response['refreshToken']['token'],
                              anti_csrf_token=response['antiCsrfToken'], contains_custom_header=False)
        raise Exception("should not have come here")
    except Exception as e:
        assert e.__class__.__name__ == 'TokenTheftError'


@mark.asyncio
async def test_basic_usage_of_sessions():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    response = await create_new_session(recipe=session_recipe, user_id="", jwt_payload={}, session_data={})
    assert response['session'] is not None
    assert response['accessToken'] is not None
    assert response['refreshToken'] is not None
    assert response['idRefreshToken'] is not None
    assert response['antiCsrfToken'] is not None
    assert len(response) == 5

    await get_session(recipe=session_recipe, access_token=response['accessToken']['token'],
                      anti_csrf_token=response['antiCsrfToken'], do_anti_csrf_check=True, contains_custom_header=False)

    assert AllowedProcessStates.CALLING_SERVICE_IN_VERIFY not in ProcessState.get_instance().history

    response2 = await refresh_session(recipe=session_recipe, refresh_token=response['refreshToken']['token'],
                                      anti_csrf_token=response['antiCsrfToken'], contains_custom_header=False)
    assert response2['session'] is not None
    assert response2['accessToken'] is not None
    assert response2['refreshToken'] is not None
    assert response2['idRefreshToken'] is not None
    assert response2['antiCsrfToken'] is not None
    assert len(response2) == 5

    response3 = await get_session(recipe=session_recipe, access_token=response2['accessToken']['token'],
                                  anti_csrf_token=response2['antiCsrfToken'], do_anti_csrf_check=True,
                                  contains_custom_header=False)

    assert AllowedProcessStates.CALLING_SERVICE_IN_VERIFY in ProcessState.get_instance().history
    assert response3['session'] is not None
    assert response3['accessToken'] is not None
    assert len(response3) == 2

    ProcessState.get_instance().reset()

    response4 = await get_session(recipe=session_recipe, access_token=response3['accessToken']['token'],
                                  anti_csrf_token=response2['antiCsrfToken'], do_anti_csrf_check=True,
                                  contains_custom_header=False)

    assert AllowedProcessStates.CALLING_SERVICE_IN_VERIFY not in ProcessState.get_instance().history
    assert response4['session'] is not None
    assert 'accessToken' not in response4
    assert len(response4) == 1

    response5 = await revoke_session(response4['session']['handle'])
    assert response5 == True

@mark.asyncio
async def test_session_verify_with_anti_csrf_present():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    response = await create_new_session(recipe=session_recipe, user_id="", jwt_payload={}, session_data={})
    response2 = await get_session(recipe=session_recipe, access_token=response['accessToken']['token'],
                                  anti_csrf_token=response['antiCsrfToken'], do_anti_csrf_check=True,
                                  contains_custom_header=True)

    assert response2['session'] is not None
    assert len(response2['session'].keys()) == 3

    response3 = await get_session(recipe=session_recipe, access_token=response['accessToken']['token'],
                                  anti_csrf_token=response['antiCsrfToken'], do_anti_csrf_check=False,
                                  contains_custom_header=False)
    assert response3['session'] is not None
    assert len(response3['session']) == 3



@mark.asyncio
async def test_session_verify_with_anti_csrf_present():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    response = await create_new_session(recipe=session_recipe, user_id="", jwt_payload={}, session_data={})
    response2 = await get_session(recipe=session_recipe, access_token=response['accessToken']['token'],
                                  anti_csrf_token=None, do_anti_csrf_check=False,
                                  contains_custom_header=True)

    assert response2['session'] is not None
    assert len(response2['session'].keys()) == 3

    try:
        response3 = await get_session(recipe=session_recipe, access_token=response['accessToken']['token'],
                                      anti_csrf_token=None, do_anti_csrf_check=True,
                                      contains_custom_header=False)
        raise Exception('should not have come here')
    except Exception as e:
        assert e.__class__.__name__ == 'TryRefreshTokenError'



@mark.asyncio
async def test_revoking_of_sessions():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    # create a simple session and revoke it with the session handle
    response = await create_new_session(recipe=session_recipe, user_id="someUniqueUserId", jwt_payload={},
                                        session_data={})
    response2 = await revoke_session(session_handle=response['session']['handle'])
    assert response2 is True

    response3 = await get_all_session_handles_for_user(user_id='someUniqueUserId')
    assert len(response3) == 0

    # create multiple sessions with the same userID and use revokeAllSessionsForUser to revoke sessions
    await create_new_session(recipe=session_recipe, user_id="someUniqueUserId", jwt_payload={},
                                            session_data={})
    await create_new_session(recipe=session_recipe, user_id="someUniqueUserId", jwt_payload={},
                             session_data={})
    session_id_response = await get_all_session_handles_for_user(user_id='someUniqueUserId')
    assert len(session_id_response) == 2

    response = await revoke_all_sessions_for_user(user_id='someUniqueUserId')
    assert len(response) == 2

    response = await get_all_session_handles_for_user(user_id='someUniqueUserId')
    assert len(response) == 0

    #revoke a session with a user id which does not exist.
    response2 = await revoke_session(session_handle='x')
    assert response2 is False

    #revoke a session with a user id which does not exist.
    #TODO: in node sdk  this method returns true/false, this method returns a list.
    response2 = await revoke_all_sessions_for_user(user_id='x')
    assert len(response2) == 0

@mark.asyncio
async def test_manipulating_session_data():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    # create a simple session and revoke it with the session handle
    response = await create_new_session(recipe=session_recipe, user_id="someUniqueUserId", jwt_payload={},
                                        session_data={})
    await update_session_data(recipe=session_recipe, session_handle=response['session']['handle'], new_session_data={'key': 'value'})
    response2 = await get_session_data(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response2 == {'key': 'value'}

    await update_session_data(recipe=session_recipe, session_handle=response['session']['handle'], new_session_data={'key': 'value2'})
    response2 = await get_session_data(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response2 == {'key': 'value2'}

    try:
        await update_session_data(recipe=session_recipe, session_handle='x',
                                  new_session_data={'key': 'value2'})
        assert False
    except Exception as e:
        assert e.__class__.__name__ == 'UnauthorisedError'

@mark.asyncio
async def test_null_and_undefined_values_passed_for_session_data():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    # create a simple session and revoke it with the session handle
    response = await create_new_session(recipe=session_recipe, user_id="", jwt_payload={},
                                        session_data=None)
    response2 = await get_session_data(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response2 == {}

    await update_session_data(recipe=session_recipe, session_handle=response['session']['handle'], new_session_data={'key': 'value'})
    response3 = await get_session_data(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response3 == {'key': 'value'}

    await update_session_data(recipe=session_recipe, session_handle=response['session']['handle'], new_session_data={})
    response4 = await get_session_data(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response4 == {}

    await update_session_data(recipe=session_recipe, session_handle=response['session']['handle'], new_session_data={'key': 'value 2'})
    response5 = await get_session_data(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response5 == {'key': 'value 2'}

    await update_session_data(recipe=session_recipe, session_handle=response['session']['handle'], new_session_data={})
    response6 = await get_session_data(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response6 == {}


@mark.asyncio
async def test_manipulating_jwt_payload():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    # create a simple session and revoke it with the session handle
    response = await create_new_session(recipe=session_recipe, user_id="", jwt_payload={},
                                        session_data=None)
    response2 = await update_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'], new_jwt_payload={'key' : 'value'})
    response2 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response2 == {'key' : 'value'}

    response3 = await update_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'], new_jwt_payload={'key' : 'value2'})
    response3 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response3 == {'key' : 'value2'}

    try:
         await update_jwt_payload(recipe=session_recipe, session_handle='x',
                                             new_jwt_payload={'key': 'value2'})
         raise Exception("should not come here")
    except Exception as e:
        assert e.__class__.__name__ == 'UnauthorisedError'



@mark.asyncio
async def test_null_and_undefined_values_passed_for_jwt_payload():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    # create a simple session and revoke it with the session handle
    response = await create_new_session(recipe=session_recipe, user_id="", jwt_payload={},
                                        session_data=None)
    response2 = await update_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'], new_jwt_payload={'key' : 'value'})
    response2 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response2 == {'key' : 'value'}

    response3 = await update_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'], new_jwt_payload={'key' : 'value2'})
    response3 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response3 == {'key' : 'value2'}

    try:
         await update_jwt_payload(recipe=session_recipe, session_handle='x',
                                             new_jwt_payload={'key': 'value2'})
         raise Exception("should not come here")
    except Exception as e:
        assert e.__class__.__name__ == 'UnauthorisedError'


@mark.asyncio
async def test_null_and_undefined_values_passed_for_jwt_payload():
    start_st()
    app = FastAPI()

    init(app, {
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN'
            }
        )],
    })

    session_recipe = SessionRecipe.get_instance()
    # create a simple session and revoke it with the session handle
    response = await create_new_session(recipe=session_recipe, user_id="", jwt_payload={},
                                        session_data=None)
    response2 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response2 == {}

    response2 = await update_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'], new_jwt_payload={'key': 'value'})
    response2 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response2 == {'key': 'value'}

    response3 = await update_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'], new_jwt_payload={'key': 'value2'})
    response3 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response3 == {'key': 'value2'}

    response4 = await update_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'], new_jwt_payload={})
    response4 = await get_jwt_payload(recipe=session_recipe, session_handle=response['session']['handle'])
    assert response4 == {}


# @mark.asyncio
# async def test_token_theft_detection():
#     start_st()
#     session = await create_new_session('userId', {}, {})
#     refreshed_session = await refresh_session(session['refreshToken']['token'], session['antiCsrfToken'])
#     await get_session(refreshed_session['accessToken']['token'], refreshed_session['antiCsrfToken'], True)
#     try:
#         await refresh_session(session['refreshToken']['token'], session['antiCsrfToken'])
#         assert False
#     except SuperTokensTokenTheftError as e:
#         assert e.user_id == 'userId'
#         assert e.session_handle == session['session']['handle']
#         assert True
#
#
# @mark.asyncio
# async def test_basic_usage_of_sessions():
#     start_st()
#     session = await create_new_session('userId', {}, {})
#     validate(session, session_with_anti_csrf)
#
#     await get_session(session['accessToken']['token'], session['antiCsrfToken'], True)
#     assert not ProcessState.get_service_called()
#
#     refreshed_session_1 = await refresh_session(session['refreshToken']['token'], session['antiCsrfToken'])
#     validate(refreshed_session_1, session_with_anti_csrf)
#
#     updated_session = await get_session(refreshed_session_1['accessToken']['token'],
#                                         refreshed_session_1['antiCsrfToken'], True)
#     assert ProcessState.get_service_called()
#     validate(updated_session, session_verify_with_access_token)
#
#     non_updated_session = await get_session(updated_session['accessToken']['token'],
#                                             refreshed_session_1['antiCsrfToken'], True)
#     assert not ProcessState.get_service_called()
#     validate(non_updated_session, session_verify_without_access_token)
#
#     assert await revoke_session(non_updated_session['session']['handle'])
#
#
# @mark.asyncio
# async def test_session_verify_with_anti_csrf():
#     start_st()
#     session = await create_new_session('userId', {}, {})
#
#     session_get_1 = await get_session(session['accessToken']['token'], session['antiCsrfToken'], True)
#     validate(session_get_1, session_verify_without_access_token)
#
#     session_get_2 = await get_session(session['accessToken']['token'], session['antiCsrfToken'], False)
#     validate(session_get_2, session_verify_without_access_token)
#
#
# @mark.asyncio
# async def test_session_verify_without_anti_csrf():
#     start_st()
#     session = await create_new_session('userId', {}, {})
#
#     session_get_1 = await get_session(session['accessToken']['token'], None, False)
#     validate(session_get_1, session_verify_without_access_token)
#
#     try:
#         await get_session(session['accessToken']['token'], None, True)
#         assert False
#     except SuperTokensTryRefreshTokenError:
#         assert True
#
#
# @mark.asyncio
# async def test_revoking_of_session():
#     start_st()
#     await revoke_all_sessions_for_user('userId')
#     assert len(await get_all_session_handles_for_user('userId')) == 0
#     session = await create_new_session('userId', {}, {})
#     assert len(await get_all_session_handles_for_user('userId')) == 1
#     assert await revoke_session(session['session']['handle'])
#     assert len(await get_all_session_handles_for_user('userId')) == 0
#     await create_new_session('userId', {}, {})
#     await create_new_session('userId', {}, {})
#     assert len(await get_all_session_handles_for_user('userId')) == 2
#     assert len(await revoke_all_sessions_for_user('userId')) == 2
#     assert len(await get_all_session_handles_for_user('userId')) == 0
#     s_reset()
#     assert not await revoke_session('random')
#     assert len(await revoke_all_sessions_for_user('randomUserId')) == 0
#
#
# @mark.asyncio
# async def test_manipulating_session_data():
#     start_st()
#     session = await create_new_session('userId', {}, {})
#     session_data_1 = await get_session_data(session['session']['handle'])
#     assert session_data_1 == {}
#     await update_session_data(session['session']['handle'], {'key': 'value'})
#     session_data_2 = await get_session_data(session['session']['handle'])
#     assert session_data_2 == {'key': 'value'}
#     await update_session_data(session['session']['handle'], {'key': 'new_value'})
#     session_data_3 = await get_session_data(session['session']['handle'])
#     assert session_data_3 == {'key': 'new_value'}
#     try:
#         await update_session_data('incorrect', {'key': 'value'})
#         assert False
#     except SuperTokensUnauthorisedError:
#         assert True
#
#
# @mark.asyncio
# async def test_manipulating_jwt_data():
#     start_st()
#     session_1 = await create_new_session('userId', {}, {})
#     session_2 = await create_new_session('userId', {}, {})
#     session_data_1_1 = await get_jwt_payload(session_1['session']['handle'])
#     assert session_data_1_1 == {}
#     session_data_2_1 = await get_jwt_payload(session_2['session']['handle'])
#     assert session_data_2_1 == {}
#
#     await update_jwt_payload(session_1['session']['handle'], {'key': 'value'})
#     session_data_1_2 = await get_jwt_payload(session_1['session']['handle'])
#     assert session_data_1_2 == {'key': 'value'}
#     session_data_2_2 = await get_jwt_payload(session_2['session']['handle'])
#     assert session_data_2_2 == {}
#
#     try:
#         await update_jwt_payload('incorrect', {'key': 'value'})
#         assert False
#     except SuperTokensUnauthorisedError:
#         assert True
#
#
# @mark.asyncio
# async def test_anti_csrf_disabled_for_core():
#     set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
#     start_st()
#     session = await create_new_session('userId', {}, {})
#
#     session_get_1 = await get_session(session['accessToken']['token'], None, False)
#     validate(session_get_1, session_verify_without_access_token)
#
#     session_get_2 = await get_session(session['accessToken']['token'], None, True)
#     validate(session_get_2, session_verify_without_access_token)
#
#
# @mark.asyncio
# async def test_token_theft_detection_with_api_key():
#     set_key_value_in_config("api_keys", "asckjsbdalvkjbasdlvjbalskdjvbaldkj")
#     start_st()
#     Querier.init_instance(None, "asckjsbdalvkjbasdlvjbalskdjvbaldkj")
#     session = await create_new_session('userId', {}, {})
#     refreshed_session = await refresh_session(session['refreshToken']['token'], session['antiCsrfToken'])
#     await get_session(refreshed_session['accessToken']['token'], refreshed_session['antiCsrfToken'], True)
#     try:
#         await refresh_session(session['refreshToken']['token'], session['antiCsrfToken'])
#         assert False
#     except SuperTokensTokenTheftError as e:
#         assert e.user_id == 'userId'
#         assert e.session_handle == session['session']['handle']
#         assert True
#
#
# @mark.asyncio
# async def test_query_without_api_key():
#     set_key_value_in_config("api_keys", "asckjsbdalvkjbasdlvjbalskdjvbaldkj")
#     start_st()
#     try:
#         version = await Querier.get_instance().get_api_version()
#         if (version != "2.0" and "com-" in environ['SUPERTOKENS_PATH']) or (
#                 find_max_version([version], ["2.3"]) == version and version != "2.3" and "supertokens-" in environ[
#             'SUPERTOKENS_PATH']):
#             assert False
#     except SuperTokensGeneralError as e:
#         assert "Invalid API key" in str(e)
