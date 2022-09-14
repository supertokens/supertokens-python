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
from supertokens_python.ingredients.emaildelivery.types import (
    EmailContent,
    EmailDeliveryConfig,
    EmailDeliveryInterface,
    SMTPServiceInterface,
    SMTPSettings,
    SMTPSettingsFrom,
)
from supertokens_python.querier import Querier
from supertokens_python.recipe import (
    passwordless,
    session,
    thirdpartypasswordless,
    emailverification,
)
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenOkResult,
)
from supertokens_python.recipe.passwordless import ContactEmailOnlyConfig
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginEmailTemplateVars,
)
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.recipe_implementation import (
    RecipeImplementation as SessionRecipeImplementation,
)
from supertokens_python.recipe.session.session_functions import create_new_session
from supertokens_python.recipe.emailverification.asyncio import (
    create_email_verification_token,
)
from supertokens_python.recipe.thirdparty.providers import Github
from supertokens_python.recipe.thirdpartypasswordless.asyncio import (
    passwordlessSigninup,
    thirdparty_sign_in_up,
)
from supertokens_python.recipe.thirdpartypasswordless.emaildelivery.services.smtp import (
    SMTPService,
)
from supertokens_python.recipe.emailverification.emaildelivery.services.smtp import (
    SMTPService as EVSMTPService,
)
from supertokens_python.recipe.thirdpartypasswordless.interfaces import (
    ThirdPartySignInUpOkResult,
)
from supertokens_python.recipe.thirdpartypasswordless.types import (
    EmailTemplateVars,
)
from supertokens_python.recipe.emailverification.types import (
    User as EVUser,
    VerificationEmailTemplateVars,
)
from supertokens_python.utils import is_version_gte
from tests.utils import (
    clean_st,
    email_verify_token_request,
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
            thirdpartypasswordless.init(
                contact_config=ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                providers=[
                    Github(client_id="", client_secret="")
                ],  # Note: providers must be set to init tp recipe
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await thirdparty_sign_in_up(
        "supertokens", "test-user-id", "test@example.com"
    )

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, ThirdPartySignInUpOkResult)
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
            thirdpartypasswordless.init(
                contact_config=ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                providers=[
                    Github(client_id="", client_secret="")
                ],  # Note: providers must be set to init tp recipe
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await thirdparty_sign_in_up(
        "supertokens", "test-user-id", "test@example.com"
    )

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, ThirdPartySignInUpOkResult)
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
            thirdpartypasswordless.init(
                contact_config=ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                providers=[
                    Github(client_id="", client_secret="")
                ],  # Note: providers must be set to init tp recipe
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await thirdparty_sign_in_up(
        "supertokens", "test-user-id", "test@example.com"
    )

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, ThirdPartySignInUpOkResult)
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
            thirdpartypasswordless.init(
                contact_config=ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                providers=[
                    Github(client_id="", client_secret="")
                ],  # Note: providers must be set to init tp recipe
            ),
            session.init(),
        ],
    )
    start_st()

    resp = await thirdparty_sign_in_up(
        "supertokens", "test-user-id", "test@example.com"
    )

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    assert isinstance(resp, ThirdPartySignInUpOkResult)
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


@mark.asyncio
async def test_email_verify_for_pless_user_no_callback():
    "Email verify: test pless user shouldn't trigger callback"
    get_content_called, send_raw_email_called, outer_override_called = (
        False,
        False,
        False,
    )

    def smtp_service_override(oi: SMTPServiceInterface[EmailTemplateVars]):
        async def send_raw_email_override(
            _content: EmailContent, _user_context: Dict[str, Any]
        ):
            nonlocal send_raw_email_called
            send_raw_email_called = True

        async def get_content_override(
            template_vars: EmailTemplateVars, _user_context: Dict[str, Any]
        ) -> EmailContent:
            nonlocal get_content_called
            get_content_called = True

            assert isinstance(template_vars, PasswordlessLoginEmailTemplateVars)

            return EmailContent(
                body="Custom body",
                to_email=template_vars.email,  # type: ignore
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
            emailverification.init(mode="OPTIONAL"),
            thirdpartypasswordless.init(
                contact_config=ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                providers=[],
                email_delivery=EmailDeliveryConfig(
                    service=email_delivery_service,
                    override=email_delivery_override,
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        return

    pless_response = await passwordlessSigninup("test@example.com", None, {})
    create_token = await create_email_verification_token(pless_response.user.user_id)

    assert isinstance(create_token, CreateEmailVerificationTokenOkResult)
    # TODO: Replaced CreateEmailVerificationTokenEmailAlreadyVerifiedError. Confirm if this is correct.

    assert (
        all([outer_override_called, get_content_called, send_raw_email_called]) is False
    )


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
            thirdpartypasswordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            ),
            session.init(),
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
            thirdpartypasswordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            ),
            session.init(),
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
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/passwordless/login"
        ).mock(side_effect=api_side_effect)
        try:
            sign_in_up_request(driver_config_client, "test@example.com", True)
        except Exception as e:
            assert str(e) == "CUSTOM_ERR"
            assert mocked_route.called

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

    async def create_and_send_custom_email(
        input_: EmailTemplateVars, _: Dict[str, Any]
    ):
        nonlocal email, code_lifetime, url_with_link_code, user_input_code
        assert isinstance(input_, PasswordlessLoginEmailTemplateVars)
        email = input_.email
        code_lifetime = input_.code_life_time
        url_with_link_code = input_.url_with_link_code
        user_input_code = input_.user_input_code

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
            thirdpartypasswordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(
                    create_and_send_custom_email=create_and_send_custom_email,
                ),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            ),
            session.init(),
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
            assert isinstance(template_vars, PasswordlessLoginEmailTemplateVars)
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
            thirdpartypasswordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                email_delivery=EmailDeliveryConfig(
                    service=None,
                    override=email_delivery_override,
                ),
            ),
            session.init(),
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

            assert isinstance(template_vars, PasswordlessLoginEmailTemplateVars)
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
            thirdpartypasswordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                email_delivery=EmailDeliveryConfig(
                    service=email_delivery_service,
                    override=email_delivery_override,
                ),
            ),
            session.init(),
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
