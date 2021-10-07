# """
# Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.
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
# """
# import asyncio
# import json
#
# from fastapi import FastAPI
# from fastapi.requests import Request
# from fastapi.testclient import TestClient
# from pytest import fixture
# from pytest import mark
#
# from supertokens_python import init, session, emailpassword
# from supertokens_python.emailpassword.interfaces import APIInterface, RecipeInterface
# from supertokens_python.framework.fastapi import Middleware
# from supertokens_python.session import create_new_session, refresh_session, get_session
# from tests.utils import (
#     reset, setup_st, clean_st, start_st, sign_up_request
# )
#
#
# def setup_function(f):
#     reset()
#     clean_st()
#     setup_st()
#
#
# def teardown_function(f):
#     reset()
#     clean_st()
#
#
# @fixture(scope='function')
# async def driver_config_client():
#     app = FastAPI()
#     app.add_middleware(Middleware)
#
#     @app.get('/login')
#     async def login(request: Request):
#         user_id = 'userId'
#         await create_new_session(request, user_id, {}, {})
#         return {'userId': user_id}
#
#     @app.post('/refresh')
#     async def custom_refresh(request: Request):
#         await refresh_session(request)
#         return {}
#
#     @app.get('/info')
#     async def info_get(request: Request):
#         await get_session(request, True)
#         return {}
#
#     @app.get('/custom/info')
#     def custom_info(_):
#         return {}
#
#     @app.options('/custom/handle')
#     def custom_handle_options(_):
#         return {'method': 'option'}
#
#     @app.get('/handle')
#     async def handle_get(request: Request):
#         session = await get_session(request, True)
#         return {'s': session.get_handle()}
#
#     @app.post('/logout')
#     async def custom_logout(request: Request):
#         session = await get_session(request, True)
#         await session.revoke_session()
#         return {}
#
#     return TestClient(app)
#
#
#
#
# def apis_override_email_password(recipe: RecipeInterface):
#         async def sign_up(input):
#             recipe.sign_in(input)
#
#
#     return param
#
# @mark.asyncio
# async def test_that_the_handlePostEmailVerification_callback_is_called_on_successfull_verification_if_given(
#         driver_config_client: TestClient):
#     token = None
#     user_info_from_callback = None
#
#     async def custom_f(user, email_verification_url_token):
#         nonlocal token
#         token = email_verification_url_token.split("?token=")[1].split("&ride")[0]
#
#     def apis_override_email_password(param: APIInterface):
#         temp = param.email_verify_post
#
#         async def email_verify_post(token: str, api_options: APIOptions):
#             nonlocal user_info_from_callback
#
#             response = await temp(token, api_options)
#
#             if response.status == "OK":
#                 user_info_from_callback = response.user
#
#             return response
#
#         param.email_verify_post = email_verify_post
#         return param
#
#     init({
#         'supertokens': {
#             'connection_uri': "http://localhost:3567",
#         },
#         'framework': 'fastapi',
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
#         ),
#             emailpassword.init({
#                 'override': {
#                     'functions':
#                 }
#             })
#         ],
#     })
#     start_st()
#
#     response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
#     await asyncio.sleep(1)
#     assert response_1.status_code == 200
#     dict_response = json.loads(response_1.text)
#     assert dict_response["status"] == "OK"
#     user_id = dict_response["user"]["id"]
#
#     cookies = extract_all_cookies(response_1)
#
#     response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
#                                             cookies['sIdRefreshToken']['value'], response_1.headers.get('anti-csrf'),
#                                             user_id)
#     await asyncio.sleep(2)
#
#     dict_response = json.loads(response_2.text)
#     assert dict_response['status'] == 'OK'
#
#     assert token is not None
#
#     response_3 = driver_config_client.post(
#         url="/auth/user/email/verify",
#         headers={
#             "Content-Type": "application/json",
#             'anti-csrf': response_1.headers.get('anti-csrf')
#         },
#         cookies={
#             'sRefreshToken': cookies['sRefreshToken']['value'],
#             'sIdRefreshToken': cookies['sIdRefreshToken']['value'],
#         },
#         json=json.dumps({
#             "method": "token",
#             "token": token
#         })
#     )
#
#     dict_response = json.loads(response_3.text)
#     assert response_3.status_code == 200
#     assert dict_response['status'] == 'OK'
#
#     await asyncio.sleep(1)
#
#     assert user_info_from_callback.user_id == user_id
#     assert user_info_from_callback.email == "test@gmail.com"
