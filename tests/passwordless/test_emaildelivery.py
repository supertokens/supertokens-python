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

import asyncio
import json
from typing import Any, Dict, Optional

import httpx
import respx
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework import BaseRequest
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery.types import (
    EmailContent,
    EmailDeliveryConfig,
    EmailDeliveryInterface,
    SMTPServiceInterface,
    SMTPSettings,
    SMTPSettingsFrom,
)
from supertokens_python.querier import Querier
from supertokens_python.recipe import passwordless, session
from supertokens_python.recipe.passwordless.emaildelivery.services.smtp import (
    SMTPService,
)
from supertokens_python.recipe.passwordless.types import EmailTemplateVars
from supertokens_python.utils import is_version_gte
from tests.utils import (
    clean_st,
    reset,
    setup_st,
    sign_in_up_request,
    sign_in_up_request_code_resend,
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
async def test_pless_login_default_backward_compatibility(
    driver_config_client: TestClient,
):
    "Passwordless login: test default backward compatibility api being called"
    app_name = ""
    email = ""
    code_lifetime = 0
    url_with_link_code = ""
    user_input_code = ""
    resend_called = False

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
            passwordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        return

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, code_lifetime, url_with_link_code, user_input_code
        body = json.loads(request.content)

        app_name = body["appName"]
        email = body["email"]
        code_lifetime = body["codeLifetime"]
        url_with_link_code = body["urlWithLinkCode"]
        user_input_code = body["userInputCode"]

        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/passwordless/login"
        ).mock(side_effect=api_side_effect)
        resp = sign_in_up_request(driver_config_client, "test@example.com", True)
        body = resp.json()

        assert resp.status_code == 200
        assert mocked_route.called

    def code_resend_api_side_effect(request: httpx.Request):
        nonlocal app_name, email, code_lifetime, url_with_link_code, user_input_code, resend_called
        body = json.loads(request.content)

        assert body["userInputCode"] != user_input_code  # Resend generates a new code

        app_name = body["appName"]
        email = body["email"]
        code_lifetime = body["codeLifetime"]
        url_with_link_code = body["urlWithLinkCode"]
        user_input_code = body["userInputCode"]
        resend_called = True

        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/passwordless/login"
        ).mock(side_effect=code_resend_api_side_effect)
        resp = sign_in_up_request_code_resend(
            driver_config_client, body["deviceId"], body["preAuthSessionId"], True
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert app_name == "ST"
        assert email == "test@example.com"
        assert all([url_with_link_code, user_input_code, code_lifetime, resend_called])
        assert code_lifetime > 0


@mark.asyncio
async def test_pless_login_default_backward_compatibility_no_suppress_error(
    driver_config_client: TestClient,
):
    "Passwordless login: test default backward compatibility api being called, error message sent back to user"
    app_name = ""
    email = ""
    code_lifetime = 0
    url_with_link_code = ""
    user_input_code = ""

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
            passwordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        return

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, code_lifetime, url_with_link_code, user_input_code
        body = json.loads(request.content)

        app_name = body["appName"]
        email = body["email"]
        code_lifetime = body["codeLifetime"]
        url_with_link_code = body["urlWithLinkCode"]
        user_input_code = body["userInputCode"]

        return httpx.Response(500, json={"err": "CUSTOM_ERR"})

    with respx_mock(assert_all_mocked=False) as mocker:
        try:
            mocker.route(host="localhost").pass_through()
            mocker.post("https://api.supertokens.io/0/st/auth/passwordless/login").mock(
                side_effect=api_side_effect
            )
            sign_in_up_request(driver_config_client, "test@example.com", True)
        except Exception as e:
            assert str(e) == "CUSTOM_ERR"

            assert app_name == "ST"
            assert email == "test@example.com"
            assert all([url_with_link_code, user_input_code, code_lifetime])
            assert code_lifetime > 0


@mark.asyncio
async def test_pless_login_backward_compatibility(driver_config_client: TestClient):
    "Passwordless login: test backward compatibility"
    email = ""
    code_lifetime = 0
    url_with_link_code = ""
    user_input_code = ""

    class CustomEmailDeliveryService(
        passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: passwordless.EmailTemplateVars,
            user_context: Dict[str, Any],
        ):
            nonlocal email, code_lifetime, url_with_link_code, user_input_code
            email = template_vars.email
            code_lifetime = template_vars.code_life_time
            url_with_link_code = template_vars.url_with_link_code
            user_input_code = template_vars.user_input_code

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
            passwordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(
                    # create_and_send_custom_email=create_and_send_custom_email,
                ),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                email_delivery=passwordless.EmailDeliveryConfig(
                    CustomEmailDeliveryService()
                ),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        return

    resp = sign_in_up_request(driver_config_client, "test@example.com", True)
    body = resp.json()

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert all([url_with_link_code, user_input_code, code_lifetime])
    assert code_lifetime > 0

    # Resend
    email = ""
    code_lifetime = 0
    url_with_link_code = ""
    user_input_code = ""

    resp = sign_in_up_request_code_resend(
        driver_config_client, body["deviceId"], body["preAuthSessionId"]
    )

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert all([url_with_link_code, user_input_code, code_lifetime])
    assert code_lifetime > 0


@mark.asyncio
async def test_pless_login_custom_override(driver_config_client: TestClient):
    "Passwordless login: test custom override"

    email = ""
    code_lifetime = 0
    url_with_link_code = ""
    user_input_code = ""
    app_name = ""
    resend_called = False

    def email_delivery_override(oi: EmailDeliveryInterface[EmailTemplateVars]):
        oi_send_email = oi.send_email

        async def send_email(
            template_vars: EmailTemplateVars, user_context: Dict[str, Any]
        ):
            nonlocal email, url_with_link_code, user_input_code, code_lifetime
            email = template_vars.email
            url_with_link_code = template_vars.url_with_link_code
            user_input_code = template_vars.user_input_code
            code_lifetime = template_vars.code_life_time

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
            passwordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                email_delivery=EmailDeliveryConfig(
                    service=None,
                    override=email_delivery_override,
                ),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        return

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, code_lifetime, url_with_link_code, user_input_code
        body = json.loads(request.content)
        app_name = body["appName"]

        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/passwordless/login"
        ).mock(side_effect=api_side_effect)
        resp = sign_in_up_request(driver_config_client, "test@example.com", True)
        body = resp.json()

        assert resp.status_code == 200
        assert mocked_route.called

    def code_resend_api_side_effect(request: httpx.Request):
        nonlocal app_name, email, code_lifetime, url_with_link_code, user_input_code, resend_called
        body = json.loads(request.content)

        app_name = body["appName"]
        email = body["email"]
        code_lifetime = body["codeLifetime"]
        url_with_link_code = body["urlWithLinkCode"]
        user_input_code = body["userInputCode"]
        resend_called = True

        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/passwordless/login"
        ).mock(side_effect=code_resend_api_side_effect)
        resp = sign_in_up_request_code_resend(
            driver_config_client, body["deviceId"], body["preAuthSessionId"], True
        )

        assert resp.status_code == 200
        assert mocked_route.called

        assert email == "test@example.com"
        assert app_name == "ST"
        assert all([url_with_link_code, user_input_code, code_lifetime, resend_called])
        assert code_lifetime > 0


@mark.asyncio
async def test_pless_login_smtp_service(driver_config_client: TestClient):
    "Passwordless login: test smtp service"
    email = ""
    code_lifetime = 0
    user_input_code = ""
    get_content_called, send_raw_email_called, outer_override_called = (
        False,
        False,
        False,
    )

    def smtp_service_override(oi: SMTPServiceInterface[EmailTemplateVars]):
        async def send_raw_email_override(
            content: EmailContent, _user_context: Dict[str, Any]
        ):
            nonlocal send_raw_email_called, email, user_input_code
            send_raw_email_called = True

            assert content.body == user_input_code
            assert content.subject == "custom subject"
            assert content.to_email == "test@example.com"
            email = content.to_email
            # Note that we aren't calling oi.send_raw_email. So Transporter won't be used.

        async def get_content_override(
            template_vars: EmailTemplateVars, _user_context: Dict[str, Any]
        ) -> EmailContent:
            nonlocal get_content_called, user_input_code, code_lifetime
            get_content_called = True

            user_input_code = template_vars.user_input_code or ""
            code_lifetime = template_vars.code_life_time

            return EmailContent(
                body=user_input_code,
                to_email=template_vars.email,
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
            passwordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                email_delivery=EmailDeliveryConfig(
                    service=email_delivery_service,
                    override=email_delivery_override,
                ),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        return

    resp = sign_in_up_request(driver_config_client, "test@example.com", True)
    body = resp.json()

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert all([outer_override_called, get_content_called, send_raw_email_called])
    assert code_lifetime > 0

    # Resend:
    email = ""
    code_lifetime = 0
    user_input_code = ""
    get_content_called, send_raw_email_called, outer_override_called = (
        False,
        False,
        False,
    )

    resp = sign_in_up_request_code_resend(
        driver_config_client, body["deviceId"], body["preAuthSessionId"], True
    )

    assert resp.status_code == 200

    assert email == "test@example.com"
    assert all([outer_override_called, get_content_called, send_raw_email_called])
    assert code_lifetime > 0


@mark.asyncio
async def test_magic_link_uses_correct_origin(
    driver_config_client: TestClient,
):
    login_url = ""

    def get_origin(req: Optional[BaseRequest], _: Dict[str, Any]) -> str:
        if req is not None:
            value = req.get_header("origin")
            if value is not None:
                return value
        return "localhost:3000"

    class CustomEmailService(
        passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: passwordless.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal login_url
            login_url = template_vars.url_with_link_code

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            origin=get_origin,
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            passwordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                email_delivery=passwordless.EmailDeliveryConfig(CustomEmailService()),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_in_up_request(driver_config_client, "random@gmail.com", True)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    response_1 = driver_config_client.post(
        url="/auth/signinup/code",
        headers={"origin": "http://localhost:5050"},
        json={"email": "random@gmail.com"},
    )
    await asyncio.sleep(1)

    assert response_1.status_code == 200
    assert "http://localhost:5050" in login_url
