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
from typing import Any, Dict, Union

import httpx
import respx
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery.types import (
    EmailContent,
    EmailDeliveryConfig,
    EmailDeliveryInterface,
    SMTPServiceInterface,
    SMTPSettings,
    SMTPSettingsFrom,
)
from supertokens_python.recipe import session, thirdparty, emailverification
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.recipe_implementation import (
    RecipeImplementation as SessionRecipeImplementation,
)
from supertokens_python.recipe.session.session_functions import create_new_session
from supertokens_python.recipe.thirdparty.asyncio import sign_in_up
from supertokens_python.recipe.emailverification.emaildelivery.services.smtp import (
    SMTPService,
)
from supertokens_python.recipe.thirdparty.interfaces import SignInUpOkResult
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdparty.types import (
    AccessTokenAPI,
    AuthorisationRedirectAPI,
    UserInfo,
    UserInfoEmail,
)
from tests.utils import clean_st, email_verify_token_request, reset, setup_st, start_st
from supertokens_python.recipe.emailverification.types import (
    User as EVUser,
    VerificationEmailTemplateVars,
)

respx_mock = respx.MockRouter


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@fixture(scope="function")
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    @app.get("/login")
    async def login(_request: Request):  # type: ignore
        user_id = "userId"
        # await create_new_session(request, user_id, {}, {})
        return {"userId": user_id}

    return TestClient(app)


class CustomProvider(Provider):
    async def get_profile_info(
        self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        return UserInfo(
            user_id=auth_code_response["id"],
            email=UserInfoEmail(auth_code_response["email"], True),
        )

    def get_authorisation_redirect_api_info(
        self, user_context: Dict[str, Any]
    ) -> AuthorisationRedirectAPI:
        return AuthorisationRedirectAPI("https://example.com/oauth/auth", {})

    def get_access_token_api_info(
        self,
        redirect_uri: str,
        auth_code_from_request: str,
        user_context: Dict[str, Any],
    ) -> AccessTokenAPI:
        return AccessTokenAPI("https://example.com/oauth/token", {})

    def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]:
        return

    def get_client_id(self, user_context: Dict[str, Any]) -> str:
        return "foo"


@mark.asyncio
async def test_email_verify_default_backward_compatibility(
    driver_config_client: TestClient,
):
    "Email verify: test default backward compatibility api being called"
    app_name = ""
    email = ""
    email_verify_url = ""

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailverification.init(mode="OPTIONAL"),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[CustomProvider("CUSTOM", True)]
                )
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await sign_in_up("supertokens", "test-user-id", "test@example.com")

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, SignInUpOkResult)
    user_id = resp.user.user_id
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, email_verify_url
        body = json.loads(request.content)

        app_name = body["appName"]
        email = body["email"]
        email_verify_url = body["emailVerifyURL"]

        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/email/verify"
        ).mock(side_effect=api_side_effect)
        resp = email_verify_token_request(
            driver_config_client,
            response["accessToken"]["token"],
            response["idRefreshToken"]["token"],
            response.get("antiCsrf", ""),
            user_id,
            True,
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert app_name == "ST"
        assert email == "test@example.com"
        assert email_verify_url != ""


@mark.asyncio
async def test_email_verify_default_backward_compatibility_supress_error(
    driver_config_client: TestClient,
):
    "Email verify: test default backward compatibility api being called, error message not sent back to user"
    app_name = ""
    email = ""
    email_verify_url = ""

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailverification.init(mode="OPTIONAL"),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[CustomProvider("CUSTOM", True)]
                )
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await sign_in_up("supertokens", "test-user-id", "test@example.com")

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, SignInUpOkResult)
    user_id = resp.user.user_id
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, email_verify_url
        body = json.loads(request.content)

        app_name = body["appName"]
        email = body["email"]
        email_verify_url = body["emailVerifyURL"]

        return httpx.Response(500, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/email/verify"
        ).mock(side_effect=api_side_effect)
        resp = email_verify_token_request(
            driver_config_client,
            response["accessToken"]["token"],
            response["idRefreshToken"]["token"],
            response.get("antiCsrf", ""),
            user_id,
            True,
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert app_name == "ST"
        assert resp.json()["status"] == "OK"
        assert email == "test@example.com"
        assert email_verify_url != ""


@mark.asyncio
async def test_email_verify_backward_compatibility(driver_config_client: TestClient):
    "Email verify: test backward compatibility"
    email = ""
    email_verify_url = ""

    async def create_and_send_custom_email(
        input_: EVUser, email_verification_link: str, _: Dict[str, Any]
    ):
        nonlocal email, email_verify_url
        email = input_.email
        email_verify_url = email_verification_link

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailverification.init(
                mode="OPTIONAL",
                create_and_send_custom_email=create_and_send_custom_email,
            ),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[CustomProvider("CUSTOM", True)]
                )
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await sign_in_up("supertokens", "test-user-id", "test@example.com")

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, SignInUpOkResult)
    user_id = resp.user.user_id
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    resp = email_verify_token_request(
        driver_config_client,
        response["accessToken"]["token"],
        response["idRefreshToken"]["token"],
        response.get("antiCsrf", ""),
        user_id,
        True,
    )

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert email_verify_url != ""


@mark.asyncio
async def test_email_verify_custom_override(driver_config_client: TestClient):
    "Email verify: test custom override"
    app_name = ""
    email = ""
    email_verify_url = ""

    def email_delivery_override(
        oi: EmailDeliveryInterface[VerificationEmailTemplateVars],
    ):
        oi_send_email = oi.send_email

        async def send_email(
            template_vars: VerificationEmailTemplateVars, user_context: Dict[str, Any]
        ):
            nonlocal email, email_verify_url
            assert isinstance(template_vars, VerificationEmailTemplateVars)
            email = template_vars.user.email
            email_verify_url = template_vars.email_verify_link
            await oi_send_email(template_vars, user_context)

        oi.send_email = send_email
        return oi

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailverification.init(
                mode="OPTIONAL",
                email_delivery=EmailDeliveryConfig(
                    service=None,
                    override=email_delivery_override,
                ),
            ),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[CustomProvider("CUSTOM", True)]
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await sign_in_up("supertokens", "test-user-id", "test@example.com")

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, SignInUpOkResult)
    user_id = resp.user.user_id
    assert isinstance(user_id, str)
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, email_verify_url
        body = json.loads(request.content)
        app_name = body["appName"]

        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/email/verify"
        ).mock(side_effect=api_side_effect)
        resp = email_verify_token_request(
            driver_config_client,
            response["accessToken"]["token"],
            response["idRefreshToken"]["token"],
            response.get("antiCsrf", ""),
            user_id,
            True,
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert app_name == "ST"
        assert email == "test@example.com"
        assert email_verify_url != ""


@mark.asyncio
async def test_email_verify_smtp_service(driver_config_client: TestClient):
    "Email verify: test smtp service"
    email = ""
    email_verify_url = ""
    get_content_called, send_raw_email_called, outer_override_called = (
        False,
        False,
        False,
    )

    def smtp_service_override(oi: SMTPServiceInterface[VerificationEmailTemplateVars]):
        async def send_raw_email_override(
            content: EmailContent, _user_context: Dict[str, Any]
        ):
            nonlocal send_raw_email_called, email
            send_raw_email_called = True

            assert content.body == email_verify_url
            assert content.subject == "custom subject"
            assert content.to_email == "test@example.com"
            email = content.to_email
            # Note that we aren't calling oi.send_raw_email. So Transporter won't be used.

        async def get_content_override(
            template_vars: VerificationEmailTemplateVars, _user_context: Dict[str, Any]
        ) -> EmailContent:
            nonlocal get_content_called, email_verify_url
            get_content_called = True

            assert isinstance(template_vars, VerificationEmailTemplateVars)
            email_verify_url = template_vars.email_verify_link

            return EmailContent(
                body=email_verify_url,
                to_email=template_vars.user.email,
                subject="custom subject",
                is_html=False,
            )

        oi.send_raw_email = send_raw_email_override
        oi.get_content = get_content_override

        return oi

    email_delivery_service = SMTPService(
        smtp_settings=SMTPSettings(
            host="",
            from_=SMTPSettingsFrom("", ""),
            password="",
            port=465,
            secure=True,
        ),
        override=smtp_service_override,
    )

    def email_delivery_override(
        oi: EmailDeliveryInterface[VerificationEmailTemplateVars],
    ) -> EmailDeliveryInterface[VerificationEmailTemplateVars]:
        oi_send_email = oi.send_email

        async def send_email_override(
            template_vars: VerificationEmailTemplateVars, user_context: Dict[str, Any]
        ):
            nonlocal outer_override_called
            outer_override_called = True
            await oi_send_email(template_vars, user_context)

        oi.send_email = send_email_override
        return oi

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailverification.init(
                mode="OPTIONAL",
                email_delivery=EmailDeliveryConfig(
                    service=email_delivery_service,
                    override=email_delivery_override,
                ),
            ),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[CustomProvider("CUSTOM", True)]
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await sign_in_up("supertokens", "test-user-id", "test@example.com")

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, SignInUpOkResult)
    user_id = resp.user.user_id
    assert isinstance(user_id, str)
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    resp = email_verify_token_request(
        driver_config_client,
        response["accessToken"]["token"],
        response["idRefreshToken"]["token"],
        response.get("antiCsrf", ""),
        user_id,
        True,
    )

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert all([outer_override_called, get_content_called, send_raw_email_called])
    assert email_verify_url != ""
