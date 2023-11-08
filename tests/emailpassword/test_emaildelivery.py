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
from typing import Any, Dict

import httpx
import respx
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark

from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery import EmailDeliveryInterface
from supertokens_python.ingredients.emaildelivery.types import (
    EmailContent,
    EmailDeliveryConfig,
    SMTPServiceInterface,
    SMTPSettings,
    SMTPSettingsFrom,
)
from supertokens_python.recipe import emailpassword, emailverification, session
from supertokens_python.recipe.emailpassword.emaildelivery.services import SMTPService
from supertokens_python.recipe.emailpassword.types import (
    EmailTemplateVars,
    PasswordResetEmailTemplateVars,
)
from supertokens_python.recipe.emailverification.emaildelivery.services import (
    SMTPService as EVSMTPService,
)
from supertokens_python.recipe.emailverification.types import (
    VerificationEmailTemplateVars,
)
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.recipe_implementation import (
    RecipeImplementation as SessionRecipeImplementation,
)
from supertokens_python.recipe.session.session_functions import create_new_session
from tests.utils import (
    clean_st,
    email_verify_token_request,
    reset,
    reset_password_request,
    setup_st,
    sign_up_request,
    start_st,
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


@mark.asyncio
async def test_reset_password_default_backward_compatibility(
    driver_config_client: TestClient,
):
    "Reset password: test default backward compatibility api being called"
    app_name = ""
    email = ""
    password_reset_url = ""

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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    sign_up_request(driver_config_client, "test@example.com", "1234abcd")

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, password_reset_url
        body = json.loads(request.content)
        app_name = body["appName"]
        email = body["email"]
        password_reset_url = body["passwordResetURL"]
        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/password/reset"
        ).mock(side_effect=api_side_effect)
        resp = reset_password_request(
            driver_config_client, "test@example.com", use_server=True
        )

        assert resp.status_code == 200
        assert mocked_route.called
        assert app_name == "ST"
        assert email == "test@example.com"
        assert password_reset_url


@mark.asyncio
async def test_reset_password_default_backward_compatibility_suppress_error(
    driver_config_client: TestClient,
):
    "Reset password: test default backward compatibility api being called, error message not sent back to user"
    app_name = ""
    email = ""
    password_reset_url = ""

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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    sign_up_request(driver_config_client, "test@example.com", "1234abcd")

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, password_reset_url
        body = json.loads(request.content)
        app_name = body["appName"]
        email = body["email"]
        password_reset_url = body["passwordResetURL"]
        return httpx.Response(500, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/password/reset"
        ).mock(side_effect=api_side_effect)
        resp = reset_password_request(
            driver_config_client, "test@example.com", use_server=True
        )

        assert resp.status_code == 200
        assert resp.json()["status"] == "OK"
        assert mocked_route.called

        assert app_name == "ST"
        assert email == "test@example.com"
        assert password_reset_url


@mark.asyncio
async def test_reset_password_backward_compatibility(driver_config_client: TestClient):
    "Reset password: test backward compatibility"
    email = ""
    password_reset_url = ""

    class CustomEmailService(
        emailpassword.EmailDeliveryInterface[emailpassword.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: emailpassword.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal email, password_reset_url
            email = template_vars.user.email
            password_reset_url = template_vars.password_reset_link

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
            emailpassword.init(
                email_delivery=emailpassword.EmailDeliveryConfig(CustomEmailService())
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    sign_up_request(driver_config_client, "test@example.com", "1234abcd")
    res = reset_password_request(driver_config_client, "test@example.com")

    assert res.status_code == 200

    assert email == "test@example.com"
    assert password_reset_url != ""


@mark.asyncio
async def test_reset_password_custom_override(driver_config_client: TestClient):
    "Reset password: test custom override"
    email = ""
    password_reset_url = ""
    app_name = ""

    def email_delivery_override(oi: EmailDeliveryInterface[EmailTemplateVars]):
        oi_send_email = oi.send_email

        async def send_email(
            template_vars: EmailTemplateVars, user_context: Dict[str, Any]
        ):
            nonlocal email, password_reset_url
            email = template_vars.user.email
            assert isinstance(template_vars, PasswordResetEmailTemplateVars)
            password_reset_url = template_vars.password_reset_link
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
            emailpassword.init(
                email_delivery=EmailDeliveryConfig(
                    service=None,
                    override=email_delivery_override,
                )
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    sign_up_request(driver_config_client, "test@example.com", "1234abcd")

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, password_reset_url
        body = json.loads(request.content)
        app_name = body["appName"]

        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/password/reset"
        ).mock(side_effect=api_side_effect)
        resp = reset_password_request(
            driver_config_client, "test@example.com", use_server=True
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert email == "test@example.com"
        assert password_reset_url != ""


@mark.asyncio
async def test_reset_password_custom_override_with_send_email_override(
    driver_config_client: TestClient,
):
    "Reset password: test custom override with send email override"
    email = ""
    password_reset_url = ""

    def email_delivery_override(oi: EmailDeliveryInterface[EmailTemplateVars]):
        oi_send_email = oi.send_email

        async def send_email(
            template_vars: EmailTemplateVars, user_context: Dict[str, Any]
        ):
            template_vars.user.email = "override@example.com"
            assert isinstance(template_vars, PasswordResetEmailTemplateVars)
            await oi_send_email(template_vars, user_context)

        oi.send_email = send_email
        return oi

    class CustomEmailService(
        emailpassword.EmailDeliveryInterface[emailpassword.EmailTemplateVars]
    ):
        async def send_email(
            self, template_vars: Any, user_context: Dict[str, Any]
        ) -> None:
            nonlocal email, password_reset_url
            email = template_vars.user.email
            password_reset_url = template_vars.password_reset_link

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
            emailpassword.init(
                email_delivery=EmailDeliveryConfig(
                    service=CustomEmailService(),
                    override=email_delivery_override,
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    sign_up_request(driver_config_client, "test@example.com", "1234abcd")

    resp = reset_password_request(
        driver_config_client, "test@example.com", use_server=True
    )

    assert resp.status_code == 200

    assert email == "override@example.com"
    assert password_reset_url != ""


@mark.asyncio
async def test_reset_password_smtp_service(driver_config_client: TestClient):
    "Reset password: test smtp service"
    email = ""
    password_reset_url = ""
    get_content_called, send_raw_email_called, outer_override_called = (
        False,
        False,
        False,
    )

    def smtp_service_override(oi: SMTPServiceInterface[EmailTemplateVars]):
        async def send_raw_email_override(
            content: EmailContent, _user_context: Dict[str, Any]
        ):
            nonlocal send_raw_email_called, email
            send_raw_email_called = True

            assert content.body == password_reset_url
            assert content.subject == "custom subject"
            assert content.to_email == "test@example.com"
            email = content.to_email
            # Note that we aren't calling oi.send_raw_email. So Transporter won't be used.

        async def get_content_override(
            template_vars: EmailTemplateVars, _user_context: Dict[str, Any]
        ) -> EmailContent:
            nonlocal get_content_called, password_reset_url
            get_content_called = True

            assert isinstance(template_vars, PasswordResetEmailTemplateVars)
            password_reset_url = template_vars.password_reset_link

            return EmailContent(
                body=template_vars.password_reset_link,
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
        oi: EmailDeliveryInterface[EmailTemplateVars],
    ) -> EmailDeliveryInterface[EmailTemplateVars]:
        oi_send_email = oi.send_email

        async def send_email_override(
            template_vars: EmailTemplateVars, user_context: Dict[str, Any]
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
            emailpassword.init(
                email_delivery=EmailDeliveryConfig(
                    service=email_delivery_service,
                    override=email_delivery_override,
                )
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    sign_up_request(driver_config_client, "test@example.com", "1234abcd")
    resp = reset_password_request(driver_config_client, "test@example.com")

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert all([outer_override_called, get_content_called, send_raw_email_called])
    assert password_reset_url != ""


@mark.asyncio
async def test_reset_password_for_non_existent_user(driver_config_client: TestClient):
    "Reset password: test no callback for non-existent users"
    email = ""
    password_reset_url = ""
    get_content_called, send_raw_email_called, outer_override_called = (
        False,
        False,
        False,
    )

    def smtp_service_override(oi: SMTPServiceInterface[EmailTemplateVars]):
        async def send_raw_email_override(
            content: EmailContent, _user_context: Dict[str, Any]
        ):
            nonlocal send_raw_email_called, email
            send_raw_email_called = True

            assert content.body == password_reset_url
            assert content.subject == "custom subject"
            assert content.to_email == "test@example.com"
            email = content.to_email
            # Note that we aren't calling oi.send_raw_email. So Transporter won't be used.

        async def get_content_override(
            template_vars: EmailTemplateVars, _user_context: Dict[str, Any]
        ) -> EmailContent:
            nonlocal get_content_called, password_reset_url
            get_content_called = True

            assert isinstance(template_vars, PasswordResetEmailTemplateVars)
            password_reset_url = template_vars.password_reset_link

            return EmailContent(
                body=template_vars.password_reset_link,
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
        oi: EmailDeliveryInterface[EmailTemplateVars],
    ) -> EmailDeliveryInterface[EmailTemplateVars]:
        oi_send_email = oi.send_email

        async def send_email_override(
            template_vars: EmailTemplateVars, user_context: Dict[str, Any]
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
            emailpassword.init(
                email_delivery=EmailDeliveryConfig(
                    service=email_delivery_service,
                    override=email_delivery_override,
                )
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    resp = reset_password_request(driver_config_client, "test@example.com")

    assert resp.status_code == 200

    # User doesn't exist. So our override mustn't be called.
    assert email == ""
    assert (
        all([outer_override_called, get_content_called, send_raw_email_called]) is False
    )
    assert password_reset_url == ""


# Tests for Email Verification


@mark.asyncio
async def test_email_verification_default_backward_compatibility(
    driver_config_client: TestClient,
):
    "Email verification: test default backward compatibility api being called"
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    res = sign_up_request(driver_config_client, "test@example.com", "1234abcd")
    user_id = res.json()["user"]["id"]

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    response = await create_new_session(
        s.recipe_implementation, "public", user_id, True, {}, {}, None
    )

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, email_verify_url
        body = json.loads(request.content)
        app_name = body["appName"]
        email = body["email"]
        email_verify_url = body["emailVerifyURL"]
        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        # mocker.route(host="https://api.supertokens.io/0/st/auth/email/verify").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/email/verify"
        ).mock(side_effect=api_side_effect)
        resp = email_verify_token_request(
            driver_config_client,
            response.accessToken.token,
            response.antiCsrfToken,
            user_id,
            True,
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert app_name == "ST"
        assert email == "test@example.com"
        assert email_verify_url


@mark.asyncio
async def test_email_verification_default_backward_compatibility_suppress_error(
    driver_config_client: TestClient,
):
    "Email verification: test default backward compatibility api being called, error message not sent back to user"
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    res = sign_up_request(driver_config_client, "test@example.com", "1234abcd")
    user_id = res.json()["user"]["id"]

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    response = await create_new_session(
        s.recipe_implementation, "public", user_id, True, {}, {}, None
    )

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, email_verify_url
        body = json.loads(request.content)
        app_name = body["appName"]
        email = body["email"]
        email_verify_url = body["emailVerifyURL"]
        return httpx.Response(500, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        # mocker.route(host="https://api.supertokens.io/0/st/auth/email/verify").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/email/verify"
        ).mock(side_effect=api_side_effect)
        resp = email_verify_token_request(
            driver_config_client,
            response.accessToken.token,
            response.antiCsrfToken,
            user_id,
            True,
        )

        assert resp.status_code == 200
        assert resp.json()["status"] == "OK"
        assert mocked_route.called

        assert app_name == "ST"
        assert email == "test@example.com"
        assert email_verify_url


@mark.asyncio
async def test_email_verification_backward_compatibility(
    driver_config_client: TestClient,
):
    "Email verification: test backward compatibility"
    email = ""
    email_verify_url = ""

    class CustomEmailService(
        emailverification.EmailDeliveryInterface[emailverification.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: emailverification.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal email, email_verify_url
            email = template_vars.user.email
            email_verify_url = template_vars.email_verify_link

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
                mode="REQUIRED",
                email_delivery=emailverification.EmailDeliveryConfig(
                    CustomEmailService()
                ),
            ),
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    res = sign_up_request(driver_config_client, "test@example.com", "1234abcd")
    user_id = res.json()["user"]["id"]

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    response = await create_new_session(
        s.recipe_implementation, "public", user_id, True, {}, {}, None
    )

    res = email_verify_token_request(
        driver_config_client,
        response.accessToken.token,
        response.antiCsrfToken,
        user_id,
        True,
    )

    assert res.status_code == 200

    assert email == "test@example.com"
    assert email_verify_url


@mark.asyncio
async def test_email_verification_custom_override(driver_config_client: TestClient):
    "Email verification: test custom override"
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
            email = template_vars.user.email
            assert isinstance(template_vars, VerificationEmailTemplateVars)
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    res = sign_up_request(driver_config_client, "test@example.com", "1234abcd")
    user_id = res.json()["user"]["id"]

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    response = await create_new_session(
        s.recipe_implementation, "public", user_id, True, {}, {}, None
    )

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, email_verify_url
        body = json.loads(request.content)
        app_name = body["appName"]
        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        # mocker.route(host="https://api.supertokens.io/0/st/auth/email/verify").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/email/verify"
        ).mock(side_effect=api_side_effect)
        resp = email_verify_token_request(
            driver_config_client,
            response.accessToken.token,
            response.antiCsrfToken,
            user_id,
            True,
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert app_name == "ST"
        assert email == "test@example.com"
        assert email_verify_url


@mark.asyncio
async def test_email_verification_smtp_service(driver_config_client: TestClient):
    "Email verification: test smtp service"
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
                body=template_vars.email_verify_link,
                to_email=template_vars.user.email,
                subject="custom subject",
                is_html=False,
            )

        oi.send_raw_email = send_raw_email_override
        oi.get_content = get_content_override

        return oi

    email_delivery_service = EVSMTPService(
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    res = sign_up_request(driver_config_client, "test@example.com", "1234abcd")
    user_id = res.json()["user"]["id"]

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    response = await create_new_session(
        s.recipe_implementation, "public", user_id, True, {}, {}, None
    )

    resp = email_verify_token_request(
        driver_config_client,
        response.accessToken.token,
        response.antiCsrfToken,
        user_id,
        True,
    )

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert all([outer_override_called, get_content_called, send_raw_email_called])
    assert email_verify_url
