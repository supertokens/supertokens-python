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

import json
from urllib.parse import urlencode
from datetime import datetime
from inspect import isawaitable
from base64 import b64encode
from typing import Any, Dict, Union

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory, TestCase

from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.django import middleware
from supertokens_python.framework.django.django_response import (
    DjangoResponse as SuperTokensDjangoWrapper,
)
from supertokens_python.recipe import emailpassword, session, thirdparty
from supertokens_python.recipe.emailpassword.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
    create_new_session_without_request_response,
)
from supertokens_python.recipe.session.framework.django.asyncio import verify_session

import pytest
from tests.utils import (
    clean_st,
    reset,
    setup_st,
    start_st,
    create_users,
    get_st_init_args,
)
from supertokens_python.recipe.dashboard import DashboardRecipe, InputOverrideConfig
from supertokens_python.recipe.dashboard.interfaces import RecipeInterface
from supertokens_python.framework import BaseRequest
from supertokens_python.querier import Querier
from supertokens_python.utils import is_version_gte
from supertokens_python.recipe.passwordless import PasswordlessRecipe, ContactConfig
from supertokens_python.recipe.dashboard.utils import DashboardConfig


def override_dashboard_functions(original_implementation: RecipeInterface):
    async def should_allow_access(
        request: BaseRequest, __: DashboardConfig, ___: Dict[str, Any]
    ):
        auth_header = request.get_header("authorization")
        return auth_header == "Bearer testapikey"

    original_implementation.should_allow_access = should_allow_access  # type: ignore
    return original_implementation


def get_cookies(response: HttpResponse) -> Dict[str, Any]:
    cookies: Dict[str, Any] = {}
    for key, morsel in response.cookies.items():
        cookies[key] = {"value": morsel.value, "name": key}
        for k, v in morsel.items():
            if (k in ("secure", "httponly")) and v == "":
                cookies[key][k] = None
            elif k == "samesite":
                if len(v) > 0 and v[-1] == ",":
                    v = v[:-1]
                cookies[key][k] = v
            else:
                cookies[key][k] = v
    return cookies


async def create_new_session_view(request: HttpRequest):
    await create_new_session(request, "public", "user_id")
    return JsonResponse({"foo": "bar"})


async def refresh_view(request: HttpRequest):
    await refresh_session(request)
    return JsonResponse({"foo": "bar"})


async def custom_response_view(_: HttpRequest):
    pass


async def logout_view(request: HttpRequest):
    session: Union[None, SessionContainer] = await get_session(request, True)
    if session is None:
        raise Exception("Should never come here")
    await session.revoke_session()
    return JsonResponse({"foo": "bar"})


async def handle_view(request: HttpRequest):
    session: Union[None, SessionContainer] = await get_session(request, True)
    if session is None:
        raise Exception("Should never come here")
    return JsonResponse({"s": session.get_handle()})


@verify_session(session_required=False)
async def optional_session(request: HttpRequest):
    session: Union[None, SessionContainer] = request.supertokens  # type: ignore
    if session is None:
        return JsonResponse({"s": "empty session"})
    return JsonResponse({"s": session.get_handle()})


@verify_session()
async def verify_view(request: HttpRequest):
    session: SessionContainer = request.supertokens  # type: ignore
    return JsonResponse({"handle": session.get_handle()})  # type: ignore


class SupertokensTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        reset()
        clean_st()
        setup_st()

    def tearDown(self):
        reset()
        clean_st()

    async def test_login_refresh(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="django",
            mode="asgi",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                    cookie_domain="supertokens.io",
                ),
            ],
        )

        start_st()

        my_middleware = middleware(create_new_session_view)
        request = self.factory.get("/login", {"user_id": "user_id"})
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp

        my_middleware = middleware(refresh_view)
        request = self.factory.get("/refresh", {"user_id": "user_id"})
        cookies = get_cookies(response)

        assert len(cookies["sAccessToken"]["value"]) > 0
        assert len(cookies["sRefreshToken"]["value"]) > 0

        request.COOKIES["sRefreshToken"] = cookies["sRefreshToken"]["value"]
        request.META["HTTP_ANTI_CSRF"] = response.headers["anti-csrf"]
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        refreshed_cookies = get_cookies(response)

        assert (
            refreshed_cookies["sAccessToken"]["value"]
            != cookies["sAccessToken"]["value"]
        )
        assert (
            refreshed_cookies["sRefreshToken"]["value"]
            != cookies["sRefreshToken"]["value"]
        )
        assert response.headers["anti-csrf"] is not None
        assert (
            refreshed_cookies["sAccessToken"]["domain"]
            == cookies["sAccessToken"]["domain"]
        )
        assert (
            refreshed_cookies["sRefreshToken"]["domain"]
            == cookies["sRefreshToken"]["domain"]
        )
        assert (
            refreshed_cookies["sAccessToken"]["secure"]
            == cookies["sAccessToken"]["secure"]
        )
        assert (
            refreshed_cookies["sRefreshToken"]["secure"]
            == cookies["sRefreshToken"]["secure"]
        )

    async def test_login_logout(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="django",
            mode="asgi",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                    cookie_domain="supertokens.io",
                )
            ],
        )

        start_st()

        my_middleware = middleware(create_new_session_view)
        request = self.factory.get("/login", {"user_id": "user_id"})
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        cookies = get_cookies(response)

        assert len(cookies["sAccessToken"]["value"]) > 0
        assert len(cookies["sRefreshToken"]["value"]) > 0

        my_middleware = middleware(logout_view)
        request = self.factory.post("/logout", {"user_id": "user_id"})

        request.COOKIES["sAccessToken"] = cookies["sAccessToken"]["value"]
        request.META["HTTP_ANTI_CSRF"] = response.headers["anti-csrf"]
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        logout_cookies = get_cookies(response)
        assert response.headers.get("anti-csrf") is None  # type: ignore
        assert logout_cookies["sAccessToken"]["value"] == ""
        assert logout_cookies["sRefreshToken"]["value"] == ""

    async def test_login_handle(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="django",
            mode="asgi",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                )
            ],
        )

        start_st()

        my_middleware = middleware(create_new_session_view)
        request = self.factory.get("/login", {"user_id": "user_id"})
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        cookies = get_cookies(response)

        assert len(cookies["sAccessToken"]["value"]) > 0
        assert len(cookies["sRefreshToken"]["value"]) > 0

        try:
            datetime.strptime(
                cookies["sAccessToken"]["expires"], "%a, %d %b %Y %H:%M:%S GMT"
            )
        except ValueError:
            assert False, "cookies expiry time doesn't have the correct format"

        my_middleware = middleware(handle_view)
        request = self.factory.get("/handle", {"user_id": "user_id"})

        request.COOKIES["sAccessToken"] = cookies["sAccessToken"]["value"]
        request.META["HTTP_ANTI_CSRF"] = response.headers["anti-csrf"]
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        assert "s" in json.loads(
            response.content
        )  # FIXME: Getting Unauthorized in body. Why?
        handle_cookies = get_cookies(response)

        assert not handle_cookies

    async def test_login_refresh_error_handler(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="django",
            mode="asgi",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                )
            ],
        )

        start_st()

        my_middleware = middleware(create_new_session_view)
        request = self.factory.get("/login", {"user_id": "user_id"})
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp

        my_middleware = middleware(refresh_view)
        request = self.factory.get("/refresh", {"user_id": "user_id"})
        cookies = get_cookies(response)

        assert len(cookies["sAccessToken"]["value"]) > 0
        assert len(cookies["sRefreshToken"]["value"]) > 0

        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        # not authorized because no access refresh token
        assert response.status_code == 401

    async def test_custom_response(self):
        def override_email_password_apis(original_implementation: APIInterface):
            original_func = original_implementation.email_exists_get

            async def email_exists_get(
                email: str,
                tenant_id: str,
                api_options: APIOptions,
                user_context: Dict[str, Any],
            ):
                response_dict = {"custom": True}
                api_options.response.set_status_code(203)
                api_options.response.set_json_content(response_dict)
                return await original_func(email, tenant_id, api_options, user_context)

            original_implementation.email_exists_get = email_exists_get
            return original_implementation

        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="django",
            mode="asgi",
            recipe_list=[
                emailpassword.init(
                    override=emailpassword.InputOverrideConfig(
                        apis=override_email_password_apis
                    )
                )
            ],
        )

        start_st()

        my_middleware = middleware(custom_response_view)
        request = self.factory.get("/auth/signup/email/exists?email=test@example.com")
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp

        assert response.status_code == 203
        dict_response = json.loads(response.content)
        assert dict_response["custom"]

    async def test_optional_session(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="django",
            mode="asgi",
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
            ],
        )

        start_st()

        my_middleware = middleware(optional_session)
        request = self.factory.get("/handle-session-optional")
        temp = my_middleware(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp

        assert response.status_code == 200
        dict_response = json.loads(response.content)
        assert dict_response["s"] == "empty session"

    async def test_thirdparty_parsing_works(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="django",
            mode="asgi",
            recipe_list=[
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[
                            thirdparty.ProviderInput(
                                config=thirdparty.ProviderConfig(
                                    third_party_id="apple",
                                    clients=[
                                        thirdparty.ProviderClientConfig(
                                            client_id="4398792-io.supertokens.example.service",
                                            additional_config={
                                                "keyId": "7M48Y4RYDL",
                                                "teamId": "YWQCXGJRJL",
                                                "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                            },
                                        ),
                                    ],
                                )
                            ),
                        ],
                    )
                ),
            ],
        )

        start_st()

        state = b64encode(
            json.dumps(
                {"frontendRedirectURI": "http://localhost:3000/redirect"}
            ).encode()
        ).decode()
        code = "testing"

        data = {"state": state, "code": code}

        request = self.factory.post(
            "/auth/callback/apple",
            urlencode(data).encode(),
            content_type="application/x-www-form-urlencoded",
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.content, b"")
        self.assertEqual(
            response.headers["location"],
            f"http://localhost:3000/redirect?state={state.replace('=', '%3D')}&code={code}",
        )

    @pytest.mark.asyncio
    async def test_search_with_multiple_emails(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="flask",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                ),
                DashboardRecipe.init(
                    api_key="testapikey",
                    override=InputOverrideConfig(
                        functions=override_dashboard_functions
                    ),
                ),
                emailpassword.init(),
            ],
        )

        start_st()
        querier = Querier.get_instance(DashboardRecipe.recipe_id)
        cdi_version = await querier.get_api_version()
        if not cdi_version:
            pytest.skip()
        if not is_version_gte(cdi_version, "2.20"):
            pytest.skip()
        await create_users(emailpassword=True)
        headers = {
            "content_type": "application/json",
            "HTTP_AUTHORIZATION": "Bearer testapikey",
        }
        request = self.factory.get(
            "/auth/dashboard/api/users",
            data={"limit": "10", "email": "iresh;john"},
            **headers,
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        self.assertEqual(response.status_code, 200)
        data_json = json.loads(response.content)
        self.assertEqual(len(data_json["users"]), 1)

    @pytest.mark.asyncio
    async def test_search_with_email_t(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="flask",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                ),
                DashboardRecipe.init(
                    api_key="testapikey",
                    override=InputOverrideConfig(
                        functions=override_dashboard_functions
                    ),
                ),
                emailpassword.init(),
            ],
        )

        start_st()
        querier = Querier.get_instance(DashboardRecipe.recipe_id)
        cdi_version = await querier.get_api_version()
        if not cdi_version:
            pytest.skip()
        if not is_version_gte(cdi_version, "2.20"):
            pytest.skip()
        await create_users(emailpassword=True)
        headers = {
            "content_type": "application/json",
            "HTTP_AUTHORIZATION": "Bearer testapikey",
        }
        request = self.factory.get(
            "/auth/dashboard/api/users", data={"limit": "10", "email": "t"}, **headers
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        self.assertEqual(response.status_code, 200)
        data_json = json.loads(response.content)
        self.assertEqual(len(data_json["users"]), 5)

    @pytest.mark.asyncio
    async def test_search_with_email_iresh(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="flask",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                ),
                DashboardRecipe.init(
                    api_key="testapikey",
                    override=InputOverrideConfig(
                        functions=override_dashboard_functions
                    ),
                ),
                emailpassword.init(),
            ],
        )

        start_st()
        querier = Querier.get_instance(DashboardRecipe.recipe_id)
        cdi_version = await querier.get_api_version()
        if not cdi_version:
            pytest.skip()
        if not is_version_gte(cdi_version, "2.20"):
            pytest.skip()
        await create_users(emailpassword=True)
        headers = {
            "content_type": "application/json",
            "HTTP_AUTHORIZATION": "Bearer testapikey",
        }
        request = self.factory.get(
            "/auth/dashboard/api/users",
            data={"limit": "10", "email": "iresh"},
            **headers,
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        self.assertEqual(response.status_code, 200)
        data_json = json.loads(response.content)
        self.assertEqual(len(data_json["users"]), 0)

    @pytest.mark.asyncio
    async def test_search_with_phone_plus_one(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="flask",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                ),
                DashboardRecipe.init(
                    api_key="testapikey",
                    override=InputOverrideConfig(
                        functions=override_dashboard_functions
                    ),
                ),
                PasswordlessRecipe.init(
                    contact_config=ContactConfig(contact_method="EMAIL"),
                    flow_type="USER_INPUT_CODE",
                ),
            ],
        )

        start_st()
        querier = Querier.get_instance(DashboardRecipe.recipe_id)
        cdi_version = await querier.get_api_version()
        if not cdi_version:
            pytest.skip()
        if not is_version_gte(cdi_version, "2.20"):
            pytest.skip()
        await create_users(
            passwordless=True,
        )
        headers = {
            "content_type": "application/json",
            "HTTP_AUTHORIZATION": "Bearer testapikey",
        }
        request = self.factory.get(
            "/auth/dashboard/api/users", data={"limit": "10", "phone": "+1"}, **headers
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        self.assertEqual(response.status_code, 200)
        data_json = json.loads(response.content)
        self.assertEqual(len(data_json["users"]), 3)

    @pytest.mark.asyncio
    async def test_search_with_phone_one_bracket(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="flask",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                ),
                DashboardRecipe.init(
                    api_key="testapikey",
                    override=InputOverrideConfig(
                        functions=override_dashboard_functions
                    ),
                ),
                PasswordlessRecipe.init(
                    contact_config=ContactConfig(contact_method="EMAIL"),
                    flow_type="USER_INPUT_CODE",
                ),
            ],
        )

        start_st()
        querier = Querier.get_instance(DashboardRecipe.recipe_id)
        cdi_version = await querier.get_api_version()
        if not cdi_version:
            pytest.skip()
        if not is_version_gte(cdi_version, "2.20"):
            pytest.skip()
        await create_users(passwordless=True)
        headers = {
            "content_type": "application/json",
            "HTTP_AUTHORIZATION": "Bearer testapikey",
        }
        request = self.factory.get(
            "/auth/dashboard/api/users",
            data={"limit": "10", "phone": "1("},
            **headers,
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        data_json = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data_json["users"]), 0)

    @pytest.mark.asyncio
    async def test_search_with_provider_google(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="flask",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                ),
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[
                            thirdparty.ProviderInput(
                                config=thirdparty.ProviderConfig(
                                    third_party_id="apple",
                                    clients=[
                                        thirdparty.ProviderClientConfig(
                                            client_id="4398792-io.supertokens.example.service",
                                            additional_config={
                                                "keyId": "7M48Y4RYDL",
                                                "teamId": "YWQCXGJRJL",
                                                "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                            },
                                        ),
                                    ],
                                )
                            ),
                            thirdparty.ProviderInput(
                                config=thirdparty.ProviderConfig(
                                    third_party_id="google",
                                    clients=[
                                        thirdparty.ProviderClientConfig(
                                            client_id="467101b197249757c71f",
                                            client_secret="e97051221f4b6426e8fe8d51486396703012f5bd",
                                        ),
                                    ],
                                )
                            ),
                            thirdparty.ProviderInput(
                                config=thirdparty.ProviderConfig(
                                    third_party_id="github",
                                    clients=[
                                        thirdparty.ProviderClientConfig(
                                            client_id="1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                                            client_secret="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",
                                        ),
                                    ],
                                )
                            ),
                        ],
                    )
                ),
                DashboardRecipe.init(
                    api_key="testapikey",
                    override=InputOverrideConfig(
                        functions=override_dashboard_functions
                    ),
                ),
            ],
        )

        start_st()
        querier = Querier.get_instance(DashboardRecipe.recipe_id)
        cdi_version = await querier.get_api_version()
        if not cdi_version:
            pytest.skip()
        if not is_version_gte(cdi_version, "2.20"):
            pytest.skip()
        await create_users(emailpassword=False, passwordless=False, thirdparty=True)
        headers = {
            "content_type": "application/json",
            "HTTP_AUTHORIZATION": "Bearer testapikey",
        }
        request = self.factory.get(
            "/auth/dashboard/api/users",
            data={"limit": "10", "provider": "google"},
            **headers,
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        self.assertEqual(response.status_code, 200)
        data_json = json.loads(response.content)
        self.assertEqual(len(data_json["users"]), 3)

    @pytest.mark.asyncio
    async def test_search_with_provider_google_and_phone_one(self):
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="flask",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    get_token_transfer_method=lambda _, __, ___: "cookie",
                ),
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[
                            thirdparty.ProviderInput(
                                config=thirdparty.ProviderConfig(
                                    third_party_id="apple",
                                    clients=[
                                        thirdparty.ProviderClientConfig(
                                            client_id="4398792-io.supertokens.example.service",
                                            additional_config={
                                                "keyId": "7M48Y4RYDL",
                                                "teamId": "YWQCXGJRJL",
                                                "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                            },
                                        ),
                                    ],
                                )
                            ),
                            thirdparty.ProviderInput(
                                config=thirdparty.ProviderConfig(
                                    third_party_id="google",
                                    clients=[
                                        thirdparty.ProviderClientConfig(
                                            client_id="467101b197249757c71f",
                                            client_secret="e97051221f4b6426e8fe8d51486396703012f5bd",
                                        ),
                                    ],
                                )
                            ),
                            thirdparty.ProviderInput(
                                config=thirdparty.ProviderConfig(
                                    third_party_id="github",
                                    clients=[
                                        thirdparty.ProviderClientConfig(
                                            client_id="1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                                            client_secret="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",
                                        ),
                                    ],
                                )
                            ),
                        ],
                    )
                ),
                DashboardRecipe.init(
                    api_key="testapikey",
                    override=InputOverrideConfig(
                        functions=override_dashboard_functions
                    ),
                ),
                PasswordlessRecipe.init(
                    contact_config=ContactConfig(contact_method="EMAIL"),
                    flow_type="USER_INPUT_CODE",
                ),
            ],
        )

        start_st()
        querier = Querier.get_instance(DashboardRecipe.recipe_id)
        cdi_version = await querier.get_api_version()
        if not cdi_version:
            pytest.skip()
        if not is_version_gte(cdi_version, "2.20"):
            pytest.skip()
        await create_users(emailpassword=False, passwordless=True, thirdparty=True)
        headers = {
            "content_type": "application/json",
            "HTTP_AUTHORIZATION": "Bearer testapikey",
        }
        request = self.factory.get(
            "/auth/dashboard/api/users",
            data={"limit": "10", "provider": "google", "phone": "1"},
            **headers,
        )
        temp = middleware(custom_response_view)(request)
        if not isawaitable(temp):
            raise Exception("Should never come here")
        response = await temp
        self.assertEqual(response.status_code, 200)
        data_json = json.loads(response.content)
        self.assertEqual(len(data_json["users"]), 0)

    async def test_that_verify_session_return_401_if_access_token_is_not_sent_and_middleware_is_not_added(
        self,
    ):
        args = get_st_init_args([session.init(get_token_transfer_method=lambda *_: "header")])  # type: ignore
        args.update({"framework": "django"})
        init(**args)  # type: ignore
        start_st()

        # Try with middleware
        request = self.factory.get("/verify")
        response: HttpResponse = await middleware(verify_view)(request)  # type: ignore
        assert response.status_code == 401
        assert json.loads(response.content) == {"message": "unauthorised"}

        # Try without middleware
        request = self.factory.get("/verify")
        response: HttpResponse = await verify_view(request)  # type: ignore
        assert response.status_code == 401
        assert json.loads(response.content) == {"message": "unauthorised"}

        # Create a session and get access token
        s = await create_new_session_without_request_response(
            "public", "userId", {}, {}
        )
        access_token = s.get_access_token()
        headers = {"HTTP_AUTHORIZATION": "Bearer " + access_token}

        # Now try with middleware:
        request = self.factory.get("/verify", {}, **headers)
        response: JsonResponse = await middleware(verify_view)(request)  # type: ignore
        assert response.status_code == 200
        assert list(json.loads(response.content)) == ["handle"]

        # Now try without middleware:
        request = self.factory.get("/verify", **headers)
        response: JsonResponse = await verify_view(request)  # type: ignore
        assert response.status_code == 200
        assert list(json.loads(response.content)) == ["handle"]


def test_remove_header_works():
    response = HttpResponse()
    st_response = SuperTokensDjangoWrapper(response)

    st_response.set_header("foo", "bar")
    assert st_response.get_header("foo") == "bar"
    st_response.remove_header("foo")
    assert st_response.get_header("foo") is None
