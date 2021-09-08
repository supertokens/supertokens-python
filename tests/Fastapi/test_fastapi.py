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
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pytest import fixture
import json
from supertokens_python import init, session
from supertokens_python.exceptions import GeneralError
from supertokens_python.framework.fastapi.fastapi_middleware import Middleware
from supertokens_python.session import create_new_session, refresh_session, get_session, revoke_session, Session, \
    verify_session, revoke_all_sessions_for_user, get_all_session_handles_for_user, get_session_data, \
    update_session_data, get_jwt_payload, update_jwt_payload
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
    ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE, ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE
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
        'framework': 'Fastapi',
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
        'framework': 'Fastapi',
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
    async def custom_refresh(request):
        refresh_session(request)
        return {}

    @app.options('/info')
    def custom_info_options(request):
        get_session(request, True)
        return {'method': 'option'}

    @app.get('/info')
    def custom_info(_: Session):
        return {}

    @app.options('/handle')
    def custom_handle_options(_: Session):
        return {'method': 'option'}

    @app.get('/handle')
    def custom_handle_api(request):

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

    @app.get('/login')
    async def login(request: Request):
        user_id = 'userId'
        await create_new_session(request, user_id, {}, {})
        return {'userId': user_id}

    @app.post('/refresh')
    async def custom_refresh(request: Request):
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

    @app.get('/handle')
    async def handle_get(request: Request):
        session = await get_session(request, True)
        return {'s': session.get_handle()}

    @app.post('/logout')
    async def custom_logout(request: Request):
        session = await get_session(request, True)
        await session.revoke_session()
        return {}

    return TestClient(app)


def test_login_refresh(driver_config_client: TestClient):
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'Fastapi',
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
    start_st()

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


def test_login_logout(driver_config_client: TestClient):
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'Fastapi',
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
    start_st()

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

    response_2 = driver_config_client.post(
        url='/logout',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sAccessToken': cookies_1['sAccessToken']['value'],
            'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
        }
    )
    cookies_2 = extract_all_cookies(response_2)
    assert response_2.headers.get('anti-csrf') is None
    assert cookies_2['sAccessToken']['value'] == ''
    assert cookies_2['sRefreshToken']['value'] == ''
    assert cookies_2['sIdRefreshToken']['value'] == ''
    assert cookies_2['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2['sAccessToken']['httponly']
    assert cookies_2['sRefreshToken']['httponly']
    assert cookies_2['sIdRefreshToken']['httponly']
    assert cookies_2['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sAccessToken']['secure'] is None
    assert cookies_2['sRefreshToken']['secure'] is None
    assert cookies_2['sIdRefreshToken']['secure'] is None


def test_login_info(driver_config_client: TestClient):
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'Fastapi',
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
    start_st()

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
            'sAccessToken': cookies_1['sAccessToken']['value'],
            'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
        }
    )
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_2 == {}


def test_login_handle(driver_config_client: TestClient):
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'Fastapi',
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
    start_st()

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
        url='/handle',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sAccessToken': cookies_1['sAccessToken']['value'],
            'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
        }
    )
    result_dict = json.loads(response_2.content)
    assert "s" in result_dict
