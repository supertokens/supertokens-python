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
from time import time

from fastapi import FastAPI, Depends

from supertokens_python.framework.fastapi.fastapi_middleware import Middleware
from supertokens_python import init, session
from supertokens_python.session import create_new_session, refresh_session, get_session, revoke_session, Session, \
    verify_session
from tests.utils import (
    verify_within_5_second_diff,
    reset, setup_st, clean_st, start_st, set_key_value_in_config,
    get_unix_timestamp, extract_all_cookies,
    TEST_ENABLE_ANTI_CSRF_CONFIG_KEY,
    TEST_ACCESS_TOKEN_PATH_VALUE,
    TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
    TEST_REFRESH_TOKEN_PATH_KEY_VALUE,
    TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
    TEST_COOKIE_DOMAIN_VALUE,
    TEST_COOKIE_DOMAIN_CONFIG_KEY,
    TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
    TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
    TEST_REFRESH_TOKEN_MAX_AGE_VALUE,
    TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
    TEST_COOKIE_SAME_SITE_CONFIG_KEY,
    TEST_COOKIE_SECURE_CONFIG_KEY,
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH,
    TEST_DRIVER_CONFIG_COOKIE_DOMAIN,
    TEST_DRIVER_CONFIG_COOKIE_SAME_SITE,
    TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH,
    ACCESS_CONTROL_EXPOSE_HEADER,
    ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE
)
# from supertokens_python.supertokens import (
#     set_relevant_headers_for_options_api,
#     get_all_session_handles_for_user,
#     revoke_all_sessions_for_user,
#     update_session_data,
#     supertokens_session,
#     update_jwt_payload,
#     create_new_session,
#     get_session_data,
#     get_jwt_payload,
#     refresh_session,
#     revoke_session,
#     get_session,
#     SuperTokens,
#     Session
# )

from pytest import fixture
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from fastapi.testclient import TestClient


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@fixture(scope='function')
async def client() -> TestClient:
    app = FastAPI()
    app.add_middleware(Middleware)
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework' : 'Fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN',
                'cookie_domain': 'supertokens.io'
            }
        )],
    })

    async def ff(_):
        return JSONResponse(content={'error_msg': 'try refresh token'}, status_code=401)

    #supertokens.set_try_refresh_token_error_handler(ff)

    @app.get('/login')
    async def login(request: Request):
        user_id = 'userId'

        await create_new_session((request), user_id, {}, {})
        return {'userId': user_id}

    @app.post('/refresh')
    async def refresh(request: Request):
        await refresh_session((request))
        return {}

    @app.get('/info')
    async def info_get(request: Request):
        await get_session((request), True)
        return {}

    @app.options('/info')
    async def info_options():
        return {'method': 'option'}

    @app.get('/handle')
    async def handle_api(request: Request):
        session = await get_session(request, False)
        return {'s': session.get_handle()}

    @app.options('/handle')
    async def handle_api_options(request: Request):
        return {'method': 'option'}

    @app.post('/logout')
    async def logout(request: Request):
        session = await get_session((request), True)
        await session.revoke_session()
        return {}

    @app.delete('/session/{session_handle}')
    async def remove_session(session_handle: str):
        s = await revoke_session(session_handle)
        return JSONResponse(content={'s': s})

    @app.get('/options')
    def set_options_headers():
        r = JSONResponse({})
        # set_relevant_headers_for_options_api(r)
        return r

    return TestClient(app)


@fixture(scope='function')
async def core_config_client() -> TestClient:
    app = FastAPI()
    app.add_middleware(Middleware)
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework' : 'Fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN',
                'cookie_domain': 'supertokens.io'
            }
        )],
    })
    async def ff(_):
        return JSONResponse(content={'error_msg': 'try refresh token'}, status_code=401)

    @app.get('/login')
    async def login(request: Request):
        user_id = 'userId'
        await create_new_session((request), user_id, {}, {})
        return {'userId': user_id}

    @app.post('/refresh')
    async def custom_refresh(_: Session = Depends(verify_session)):
        print('here')
        return {}

    @app.options('/info')
    def custom_info_options():
        return {'method': 'option'}

    @app.get('/info')
    def custom_info(_: Session):
        return {}

    @app.options('/handle')
    def custom_handle_options(_: Session):
        return {'method': 'option'}

    @app.get('/handle')
    def custom_handle_api(session: Session):
        return {'s': session.get_handle()}

    @app.post('/logout')
    async def custom_logout(session: Session = Depends(verify_session)):
        await session.revoke_session()
        return {}

    return TestClient(app)


@fixture(scope='function')
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(Middleware)
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework' : 'Fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN',
                'cookie_domain': 'supertokens.io'
            }
        )],
    })

    async def ff(_):
        return JSONResponse(content={'error_msg': 'try refresh token'}, status_code=401)

    # supertokens.set_try_refresh_token_error_handler(ff)

    @app.get('/login')
    async def login(request: Request):
        user_id = 'userId'
        await create_new_session(request, user_id, {}, {})
        return {'userId': user_id}

    @app.post('/refresh')
    async def custom_refresh(request : Request):
        await refresh_session(request)
        return {}

    @app.get('/info')
    async def info_get(request: Request):
        await get_session(request, True)
        return {}

    @app.get('/custom/info')
    def custom_info(_):
        return {}

    @app.options('/custom/handle')
    def custom_handle_options(_):
        return {'method': 'option'}

    @app.get('/custom/handle')
    def custom_handle_api(session):
        return {'s': session.get_handle()}

    @app.post('/logout')
    async def custom_logout(request : Request):
        session = await get_session(request, True)
        await session.revoke_session()
        return {}

    return TestClient(app)


def test_cookie_and_header_values_with_driver_config_and_csrf_enabled(driver_config_client: TestClient):
    start_st()
    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        'None')
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        False)

    response_1 = driver_config_client.get('/login')
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get('anti-csrf') is not None
    assert cookies_1['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sAccessToken']['secure'] is None
    assert cookies_1['sRefreshToken']['secure'] is None
    assert cookies_1['sIdRefreshToken']['secure'] is None

    response_2 = driver_config_client.get(
        url='/info',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sIdRefreshToken': cookies_1['sIdRefreshToken']['value'],
            'sAccessToken': cookies_1['sAccessToken']['value'],
        }
    )

    print(response_2)
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_2 == {}

    response_3 = driver_config_client.post(
        url='/refresh',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sRefreshToken': cookies_1['sRefreshToken']['value'],
            'sIdRefreshToken': cookies_1['sIdRefreshToken']['value'],
        }
    )
    print(response_3)
    cookies_3 = extract_all_cookies(response_3)

    assert cookies_3['sAccessToken']['value'] != cookies_1['sAccessToken']['value']
    assert cookies_3['sRefreshToken']['value'] != cookies_1['sRefreshToken']['value']
    assert cookies_3['sIdRefreshToken']['value'] != cookies_1['sIdRefreshToken']['value']
    assert response_3.headers.get('anti-csrf') is not None
    assert cookies_3['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_3['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_3['sAccessToken']['httponly']
    assert cookies_3['sRefreshToken']['httponly']
    assert cookies_3['sIdRefreshToken']['httponly']
    assert cookies_3['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_3['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_3['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_3['sAccessToken']['secure'] is None
    assert cookies_3['sRefreshToken']['secure'] is None
    assert cookies_3['sIdRefreshToken']['secure'] is None


    response_4 = driver_config_client.post(
        url='/logout',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sAccessToken': cookies_1['sAccessToken']['value'],
            'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
        }
    )
    cookies_4 = extract_all_cookies(response_4)
    assert response_4.headers.get('anti-csrf') is None
    assert cookies_4['sAccessToken']['value'] == ''
    assert cookies_4['sRefreshToken']['value'] == ''
    assert cookies_4['sIdRefreshToken']['value'] == ''
    assert cookies_4['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_4['sAccessToken']['httponly']
    assert cookies_4['sRefreshToken']['httponly']
    assert cookies_4['sIdRefreshToken']['httponly']
    assert cookies_4['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sAccessToken']['secure'] is None
    assert cookies_4['sRefreshToken']['secure'] is None
    assert cookies_4['sIdRefreshToken']['secure'] is None


def test_cookie_and_header_values_with_driver_config_and_csrf_disabled(driver_config_client: TestClient):
    set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        'lax')
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        False)
    start_st()

    response_1 = driver_config_client.get('/login')
    cookies_1 = extract_all_cookies(response_1)

    #assert response_1.headers.get('anti-csrf') is None
    assert cookies_1['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sAccessToken']['secure'] is None
    assert cookies_1['sRefreshToken']['secure'] is None
    assert cookies_1['sIdRefreshToken']['secure'] is None
    assert verify_within_5_second_diff(
        get_unix_timestamp(cookies_1['sAccessToken']['expires']) - int(time()),
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    )
    assert verify_within_5_second_diff(
        get_unix_timestamp(cookies_1['sRefreshToken']['expires']) - int(time()),
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    )
    assert cookies_1['sIdRefreshToken']['value'] + \
        ';' == response_1.headers['Id-Refresh-Token'][:-13]
    assert verify_within_5_second_diff(
        int(response_1.headers['Id-Refresh-Token'][-13:-3]),
        get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
    )
    #assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE

    response_2 = driver_config_client.post(
        url='/refresh',
        cookies={
            'sRefreshToken': cookies_1['sRefreshToken']['value'],
            'sIdRefreshToken': cookies_1['sIdRefreshToken']['value'],
        }
    )
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
    assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
    assert response_2.headers.get('anti-csrf') is None
    assert cookies_2['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_2['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2['sAccessToken']['httponly']
    assert cookies_2['sRefreshToken']['httponly']
    assert cookies_2['sIdRefreshToken']['httponly']
    assert cookies_2['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sAccessToken']['secure'] is None
    assert cookies_2['sRefreshToken']['secure'] is None
    assert cookies_2['sIdRefreshToken']['secure'] is None
    assert verify_within_5_second_diff(
        get_unix_timestamp(cookies_2['sAccessToken']['expires']) - int(time()),
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    )
    assert verify_within_5_second_diff(
        get_unix_timestamp(cookies_2['sRefreshToken']['expires']) - int(time()),
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    )
    assert cookies_2['sIdRefreshToken']['value'] + \
        ';' == response_2.headers['Id-Refresh-Token'][:-13]
    assert verify_within_5_second_diff(
        int(response_2.headers['Id-Refresh-Token'][-13:-3]),
        get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
    )
    assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE

    response_3 = driver_config_client.get(
        url='/custom/info',
        cookies={
            'sAccessToken': cookies_2['sAccessToken']['value'],
            'sIdRefreshToken': cookies_2['sIdRefreshToken']['value']
        }
    )
    assert response_3.status_code == 200
    cookies_3 = extract_all_cookies(response_3)
    assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert response_3.headers.get('anti-csrf') is None
    assert cookies_3.get('sRefreshToken') is None
    assert cookies_3.get('sIdRefreshToken') is None
    assert cookies_3['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_3['sAccessToken']['httponly']
    assert cookies_3['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_3['sAccessToken']['secure'] is None

    response_4 = driver_config_client.post(
        url='/custom/logout',
        cookies={
            'sAccessToken': cookies_3['sAccessToken']['value'],
            'sIdRefreshToken': cookies_2['sIdRefreshToken']['value']
        }
    )
    cookies_4 = extract_all_cookies(response_4)
    assert response_4.headers.get('anti-csrf') is None
    assert cookies_4['sAccessToken']['value'] == ''
    assert cookies_4['sRefreshToken']['value'] == ''
    assert cookies_4['sIdRefreshToken']['value'] == ''
    assert cookies_4['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_4['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_4['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_4['sAccessToken']['httponly']
    assert cookies_4['sRefreshToken']['httponly']
    assert cookies_4['sIdRefreshToken']['httponly']
    assert cookies_4['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sAccessToken']['secure'] is None
    assert cookies_4['sRefreshToken']['secure'] is None
    assert cookies_4['sIdRefreshToken']['secure'] is None
    assert verify_within_5_second_diff(
        get_unix_timestamp(cookies_4['sAccessToken']['expires']), 0
    )
    assert verify_within_5_second_diff(
        get_unix_timestamp(cookies_4['sRefreshToken']['expires']), 0
    )
    assert verify_within_5_second_diff(
        get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']), 0
    )
    assert response_4.headers['Id-Refresh-Token'] == 'remove'


#
# def test_cookie_and_header_values_with_csrf_enabled(core_config_client: TestClient):
#     set_key_value_in_config(
#         TEST_COOKIE_SAME_SITE_CONFIG_KEY,
#         TEST_COOKIE_SAME_SITE_VALUE)
#     set_key_value_in_config(
#         TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
#         TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
#     set_key_value_in_config(
#         TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
#         TEST_ACCESS_TOKEN_PATH_VALUE)
#     set_key_value_in_config(
#         TEST_COOKIE_DOMAIN_CONFIG_KEY,
#         TEST_COOKIE_DOMAIN_VALUE)
#     set_key_value_in_config(
#         TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
#         TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
#     set_key_value_in_config(
#         TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
#         TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
#     set_key_value_in_config(
#         TEST_COOKIE_SECURE_CONFIG_KEY,
#         TEST_COOKIE_SECURE_VALUE)
#     start_st()
#
#     response_1 = core_config_client.get('/login')
#     cookies_1 = extract_all_cookies(response_1)
#
#     assert response_1.headers.get('anti-csrf') is not None
#     assert cookies_1['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_1['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_1['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_1['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_1['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
#     assert cookies_1['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_1['sAccessToken']['httponly']
#     assert cookies_1['sRefreshToken']['httponly']
#     assert cookies_1['sIdRefreshToken']['httponly']
#     assert cookies_1['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_1['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_1['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_1['sAccessToken']['secure'] is None
#     assert cookies_1['sRefreshToken']['secure'] is None
#     assert cookies_1['sIdRefreshToken']['secure'] is None
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_1['sAccessToken']['expires']) - int(time()),
#         TEST_ACCESS_TOKEN_MAX_AGE_VALUE
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_1['sRefreshToken']['expires']) - int(time()),
#         TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
#     )
#     assert cookies_1['sIdRefreshToken']['value'] + \
#         ';' == response_1.headers['Id-Refresh-Token'][:-13]
#     assert verify_within_5_second_diff(
#         int(response_1.headers['Id-Refresh-Token'][-13:-3]),
#         get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
#     )
#     assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE
#
#     response_2 = core_config_client.post(
#         url='/refresh',
#         headers={
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sRefreshToken': cookies_1['sRefreshToken']['value']
#         }
#     )
#     cookies_2 = extract_all_cookies(response_2)
#     assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
#     assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
#     assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
#     assert response_2.headers.get('anti-csrf') is not None
#     assert cookies_2['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_2['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_2['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_2['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_2['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
#     assert cookies_2['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_2['sAccessToken']['httponly']
#     assert cookies_2['sRefreshToken']['httponly']
#     assert cookies_2['sIdRefreshToken']['httponly']
#     assert cookies_2['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_2['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_2['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_2['sAccessToken']['secure'] is None
#     assert cookies_2['sRefreshToken']['secure'] is None
#     assert cookies_2['sIdRefreshToken']['secure'] is None
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_2['sAccessToken']['expires']) - int(time()),
#         TEST_ACCESS_TOKEN_MAX_AGE_VALUE
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_2['sRefreshToken']['expires']) - int(time()),
#         TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
#     )
#     assert cookies_2['sIdRefreshToken']['value'] + \
#         ';' == response_2.headers['Id-Refresh-Token'][:-13]
#     assert verify_within_5_second_diff(
#         int(response_2.headers['Id-Refresh-Token'][-13:-3]),
#         get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
#     )
#     assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE
#
#     response_3 = core_config_client.get(
#         url='/info',
#         headers={
#             'anti-csrf': response_2.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_2['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_2['sIdRefreshToken']['value']
#         }
#     )
#     assert response_3.status_code == 200
#     cookies_3 = extract_all_cookies(response_3)
#     assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
#     assert response_3.headers.get('anti-csrf') is None
#     assert cookies_3.get('sRefreshToken') is None
#     assert cookies_3.get('sIdRefreshToken') is None
#     assert cookies_3['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_3['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_3['sAccessToken']['httponly']
#     assert cookies_3['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_3['sAccessToken']['secure'] is None
#
#     response_4 = core_config_client.post(
#         url='/logout',
#         headers={
#             'anti-csrf': response_2.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_3['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_2['sIdRefreshToken']['value']
#         }
#     )
#     cookies_4 = extract_all_cookies(response_4)
#     assert response_4.headers.get('anti-csrf') is None
#     assert cookies_4['sAccessToken']['value'] == ''
#     assert cookies_4['sRefreshToken']['value'] == ''
#     assert cookies_4['sIdRefreshToken']['value'] == ''
#     assert cookies_4['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_4['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_4['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
#     assert cookies_4['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_4['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
#     assert cookies_4['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_4['sAccessToken']['httponly']
#     assert cookies_4['sRefreshToken']['httponly']
#     assert cookies_4['sIdRefreshToken']['httponly']
#     assert cookies_4['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_4['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_4['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_4['sAccessToken']['secure'] is None
#     assert cookies_4['sRefreshToken']['secure'] is None
#     assert cookies_4['sIdRefreshToken']['secure'] is None
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_4['sAccessToken']['expires']), 0
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_4['sRefreshToken']['expires']), 0
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']), 0
#     )
#     assert response_4.headers['Id-Refresh-Token'] == 'remove'
#
#
# @mark.asyncio
# async def test_cookie_and_header_values_with_csrf_disabled(core_config_client: TestClient):
#     set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
#     set_key_value_in_config(
#         TEST_COOKIE_SAME_SITE_CONFIG_KEY,
#         TEST_COOKIE_SAME_SITE_VALUE)
#     set_key_value_in_config(
#         TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
#         TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
#     set_key_value_in_config(
#         TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
#         TEST_ACCESS_TOKEN_PATH_VALUE)
#     set_key_value_in_config(
#         TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
#         TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
#     set_key_value_in_config(
#         TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
#         TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
#     set_key_value_in_config(
#         TEST_COOKIE_SECURE_CONFIG_KEY,
#         TEST_COOKIE_SECURE_VALUE)
#     start_st()
#
#     response_1 = core_config_client.get('/login')
#     cookies_1 = extract_all_cookies(response_1)
#
#     assert response_1.headers.get('anti-csrf') is None
#     if compare_version(await Querier.get_instance().get_api_version(), "2.1") == "2.1":
#         assert cookies_1['sAccessToken']['domain'] == "localhost" or cookies_1['sAccessToken']['domain'] == "supertokens.io"
#         assert cookies_1['sRefreshToken']['domain'] == "localhost" or cookies_1['sRefreshToken']['domain'] == "supertokens.io"
#         assert cookies_1['sIdRefreshToken']['domain'] == "localhost" or cookies_1['sIdRefreshToken']['domain'] == "supertokens.io"
#     else:
#         assert cookies_1['sAccessToken']['domain'] == ""
#         assert cookies_1['sRefreshToken']['domain'] == ""
#         assert cookies_1['sIdRefreshToken']['domain'] == ""
#     assert cookies_1['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_1['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
#     assert cookies_1['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_1['sAccessToken']['httponly']
#     assert cookies_1['sRefreshToken']['httponly']
#     assert cookies_1['sIdRefreshToken']['httponly']
#     assert cookies_1['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_1['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_1['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_1['sAccessToken']['secure'] is None
#     assert cookies_1['sRefreshToken']['secure'] is None
#     assert cookies_1['sIdRefreshToken']['secure'] is None
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_1['sAccessToken']['expires']) - int(time()),
#         TEST_ACCESS_TOKEN_MAX_AGE_VALUE
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_1['sRefreshToken']['expires']) - int(time()),
#         TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
#     )
#     assert cookies_1['sIdRefreshToken']['value'] + \
#         ';' == response_1.headers['Id-Refresh-Token'][:-13]
#     assert verify_within_5_second_diff(
#         int(response_1.headers['Id-Refresh-Token'][-13:-3]),
#         get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
#     )
#     assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE
#
#     response_2 = core_config_client.post(
#         url='/refresh',
#         cookies={
#             'sRefreshToken': cookies_1['sRefreshToken']['value']
#         }
#     )
#     cookies_2 = extract_all_cookies(response_2)
#     assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
#     assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
#     assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
#     assert response_2.headers.get('anti-csrf') is None
#     assert cookies_2['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_2['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
#     assert cookies_2['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_2['sAccessToken']['httponly']
#     assert cookies_2['sRefreshToken']['httponly']
#     assert cookies_2['sIdRefreshToken']['httponly']
#     assert cookies_2['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_2['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_2['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_2['sAccessToken']['secure'] is None
#     assert cookies_2['sRefreshToken']['secure'] is None
#     assert cookies_2['sIdRefreshToken']['secure'] is None
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_2['sAccessToken']['expires']) - int(time()),
#         TEST_ACCESS_TOKEN_MAX_AGE_VALUE
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_2['sRefreshToken']['expires']) - int(time()),
#         TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
#     )
#     assert cookies_2['sIdRefreshToken']['value'] + \
#         ';' == response_2.headers['Id-Refresh-Token'][:-13]
#     assert verify_within_5_second_diff(
#         int(response_2.headers['Id-Refresh-Token'][-13:-3]),
#         get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
#     )
#     assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE
#
#     response_3 = core_config_client.get(
#         url='/info',
#         cookies={
#             'sAccessToken': cookies_2['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_2['sIdRefreshToken']['value']
#         }
#     )
#     assert response_3.status_code == 200
#     cookies_3 = extract_all_cookies(response_3)
#     assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
#     assert response_3.headers.get('anti-csrf') is None
#     assert cookies_3.get('sRefreshToken') is None
#     assert cookies_3.get('sIdRefreshToken') is None
#     assert cookies_3['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_3['sAccessToken']['httponly']
#     assert cookies_3['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_3['sAccessToken']['secure'] is None
#
#     response_4 = core_config_client.post(
#         url='/logout',
#         headers={
#             'anti-csrf': response_2.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_3['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_2['sIdRefreshToken']['value']
#         }
#     )
#     cookies_4 = extract_all_cookies(response_4)
#     assert response_4.headers.get('anti-csrf') is None
#     assert cookies_4['sAccessToken']['value'] == ''
#     assert cookies_4['sRefreshToken']['value'] == ''
#     assert cookies_4['sIdRefreshToken']['value'] == ''
#     assert cookies_4['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_4['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
#     assert cookies_4['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
#     assert cookies_4['sAccessToken']['httponly']
#     assert cookies_4['sRefreshToken']['httponly']
#     assert cookies_4['sIdRefreshToken']['httponly']
#     assert cookies_4['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_4['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_4['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
#     assert cookies_4['sAccessToken']['secure'] is None
#     assert cookies_4['sRefreshToken']['secure'] is None
#     assert cookies_4['sIdRefreshToken']['secure'] is None
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_4['sAccessToken']['expires']), 0
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_4['sRefreshToken']['expires']), 0
#     )
#     assert verify_within_5_second_diff(
#         get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']), 0
#     )
#     assert response_4.headers['Id-Refresh-Token'] == 'remove'
#
#
# def test_supertokens_token_theft_detection(client: TestClient):
#     start_st()
#     response_1 = client.get('/login')
#     cookies_1 = extract_all_cookies(response_1)
#     response_2 = client.post(
#         url='/refresh',
#         headers={
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sRefreshToken': cookies_1['sRefreshToken']['value']
#         }
#     )
#     cookies_2 = extract_all_cookies(response_2)
#     client.get(
#         url='/info',
#         headers={
#             'anti-csrf': response_2.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_2['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_2['sIdRefreshToken']['value']
#         }
#     )
#     response_4 = client.post(
#         url='/refresh',
#         headers={
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sRefreshToken': cookies_1['sRefreshToken']['value']
#         }
#     )
#     assert response_4.json() == {'error': 'token theft detected'}
#     assert response_4.status_code == 440 or response_4.status_code == 401
#
#
# def test_supertokens_basic_usage_of_sessions(client: TestClient):
#     start_st()
#     response_1 = client.get('/login')
#     cookies_1 = extract_all_cookies(response_1)
#
#     client.get(
#         url='/info',
#         headers={
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_1['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
#         }
#     )
#     assert not ProcessState.get_service_called()
#
#     response_3 = client.post(
#         url='/refresh',
#         headers={
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sRefreshToken': cookies_1['sRefreshToken']['value']
#         }
#     )
#     cookies_3 = extract_all_cookies(response_3)
#
#     response_4 = client.get(
#         url='/info',
#         headers={
#             'anti-csrf': response_3.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_3['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_3['sIdRefreshToken']['value']
#         }
#     )
#     cookies_4 = extract_all_cookies(response_4)
#     assert ProcessState.get_service_called()
#
#     response_5 = client.get(
#         url='/handle',
#         headers={
#             'anti-csrf': response_3.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_4['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_3['sIdRefreshToken']['value']
#         }
#     )
#     assert not ProcessState.get_service_called()
#
#     assert client.delete('/session/' + response_5.json()['s']).json()['s']
#
#
# def test_supertokens_session_verify_with_anti_csrf(client: TestClient):
#     start_st()
#     response_1 = client.get('/login')
#     cookies_1 = extract_all_cookies(response_1)
#
#     response_2 = client.get(
#         url='/info',
#         headers={
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_1['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
#         }
#     )
#     assert response_2.status_code == 200
#
#     response_3 = client.get(
#         url='/handle',
#         headers={
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sAccessToken': cookies_1['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
#         }
#     )
#     assert response_3.status_code == 200
#
#
# def test_supertokens_session_verify_without_anti_csrf(client: TestClient):
#     start_st()
#     response_1 = client.get('/login')
#     cookies_1 = extract_all_cookies(response_1)
#
#     response_2 = client.get(
#         url='/info',
#         cookies={
#             'sAccessToken': cookies_1['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
#         }
#     )
#     assert response_2.status_code == 401
#     assert response_2.json() == {'error_msg': 'try refresh token'}
#
#     response_3 = client.get(
#         url='/handle',
#         cookies={
#             'sAccessToken': cookies_1['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
#         }
#     )
#     assert response_3.status_code == 200
#
#
# @mark.asyncio
# async def test_supertokens_revoking_of_sessions():
#     start_st()
#     await revoke_all_sessions_for_user('userId')
#     assert len(await get_all_session_handles_for_user('userId')) == 0
#     session = await create_new_session(Request(scope={'type': 'http'}), 'userId', {}, {})
#     assert len(await get_all_session_handles_for_user('userId')) == 1
#     assert await revoke_session(session.get_handle())
#     assert len(await get_all_session_handles_for_user('userId')) == 0
#     await create_new_session(Request(scope={'type': 'http'}), 'userId', {}, {})
#     await create_new_session(Request(scope={'type': 'http'}), 'userId', {}, {})
#     assert len(await get_all_session_handles_for_user('userId')) == 2
#     assert len(await revoke_all_sessions_for_user('userId')) == 2
#     assert len(await get_all_session_handles_for_user('userId')) == 0
#     assert not await revoke_session('random')
#     assert len(await revoke_all_sessions_for_user('randomUserId')) == 0
#
#
# @mark.asyncio
# async def test_supertokens_manipulating_session_data():
#     start_st()
#     session = await create_new_session(Request(scope={'type': 'http'}), 'userId', {}, {})
#     session_data_1 = await get_session_data(session.get_handle())
#     assert session_data_1 == {}
#     await update_session_data(session.get_handle(), {'key': 'value'})
#     session_data_2 = await session.get_session_data()
#     assert session_data_2 == {'key': 'value'}
#     await session.update_session_data({'key': 'new_value'})
#     session_data_3 = await get_session_data(session.get_handle())
#     assert session_data_3 == {'key': 'new_value'}
#     try:
#         await update_session_data('incorrect', {'key': 'value'})
#         assert False
#     except GeneralError:
#         assert True
#
#
# @mark.asyncio
# async def test_supertokens_manipulating_jwt_data():
#     start_st()
#     session_1 = await create_new_session(Request(scope={'type': 'http'}), 'userId', {}, {})
#     session_2 = await create_new_session(Request(scope={'type': 'http'}), 'userId', {}, {})
#     session_data_1_1 = await get_jwt_payload(session_1.get_handle())
#     assert session_data_1_1 == {}
#     session_data_2_1 = await get_jwt_payload(session_2.get_handle())
#     assert session_data_2_1 == {}
#
#     await update_jwt_payload(session_1.get_handle(), {'key': 'value'})
#     session_data_1_2 = await get_jwt_payload(session_1.get_handle())
#     assert session_data_1_2 == {'key': 'value'}
#     session_data_2_2 = await get_jwt_payload(session_2.get_handle())
#     assert session_data_2_2 == {}
#
#     try:
#         await update_jwt_payload('incorrect', {'key': 'value'})
#         assert False
#     except GeneralError:
#         assert True
#
#
# def test_supertokens_anti_csrf_disabled_for_core(client: TestClient):
#     set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
#     start_st()
#     response_1 = client.get('/login')
#     cookies_1 = extract_all_cookies(response_1)
#
#     response_2 = client.get(
#         url='/info',
#         cookies={
#             'sAccessToken': cookies_1['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
#         }
#     )
#     assert response_2.status_code == 200
#
#     response_3 = client.get(
#         url='/handle',
#         cookies={
#             'sAccessToken': cookies_1['sAccessToken']['value'],
#             'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
#         }
#     )
#     assert response_3.status_code == 200
#
#
# def test_supertokens_set_options_headers_api(client):
#     response = client.get('/options')
#     assert response.headers.get(
#         'Access-Control-Allow-Headers') == 'anti-csrf, supertokens-sdk-name, supertokens-sdk-version'
#     assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
