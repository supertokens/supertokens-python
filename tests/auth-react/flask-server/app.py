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
import os
from typing import Any, Dict, List, Optional, Union

from dotenv import load_dotenv
from flask import Flask, g, jsonify, make_response, request
from flask_cors import CORS
from typing_extensions import Literal

from supertokens_python import (
    InputAppInfo,
    Supertokens,
    SupertokensConfig,
    get_all_cors_headers,
    init,
)
from supertokens_python.framework.flask.flask_middleware import Middleware
from supertokens_python.framework.request import BaseRequest
from supertokens_python.recipe import (
    emailpassword,
    emailverification,
    passwordless,
    session,
    thirdparty,
    userroles,
)
from supertokens_python.recipe.dashboard import DashboardRecipe
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface as EmailPasswordAPIInterface,
)
from supertokens_python.recipe.thirdparty.provider import Provider, RedirectUriInfo
from supertokens_python.recipe.emailpassword.interfaces import (
    APIOptions as EPAPIOptions,
)
from supertokens_python.recipe.emailpassword.types import (
    FormField,
    InputFormField,
    User,
)
from supertokens_python.recipe.emailverification import (
    EmailVerificationClaim,
    EmailVerificationRecipe,
)
from supertokens_python.recipe.emailverification import (
    InputOverrideConfig as EVInputOverrideConfig,
)
from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface as EmailVerificationAPIInterface,
)
from supertokens_python.recipe.emailverification.interfaces import (
    APIOptions as EVAPIOptions,
)
from supertokens_python.recipe.emailverification.syncio import unverify_email
from supertokens_python.recipe.jwt import JWTRecipe
from supertokens_python.recipe.passwordless import (
    ContactEmailOnlyConfig,
    ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig,
    PasswordlessRecipe,
)
from supertokens_python.recipe.passwordless.interfaces import (
    APIInterface as PasswordlessAPIInterface,
)
from supertokens_python.recipe.passwordless.interfaces import APIOptions as PAPIOptions
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session.interfaces import (
    APIInterface as SessionAPIInterface,
)
from supertokens_python.recipe.session.interfaces import APIOptions as SAPIOptions
from supertokens_python.recipe.session.interfaces import (
    SessionClaimValidator,
    SessionContainer,
)
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.interfaces import (
    APIInterface as ThirdpartyAPIInterface,
)
from supertokens_python.recipe.thirdparty.interfaces import APIOptions as TPAPIOptions
from supertokens_python.recipe.thirdparty.provider import Provider

from supertokens_python.recipe.userroles import (
    PermissionClaim,
    UserRoleClaim,
    UserRolesRecipe,
)
from supertokens_python.recipe.userroles.syncio import (
    add_role_to_user,
    create_new_role_or_add_permissions,
)
from supertokens_python.types import GeneralErrorResponse
from supertokens_python.recipe.emailpassword.syncio import get_user_by_email
from supertokens_python.syncio import delete_user

load_dotenv()


def get_api_port():
    return "8083"


def get_website_port():
    return "3031"


def get_website_domain():
    return "http://localhost:" + get_website_port()


os.environ.setdefault("SUPERTOKENS_ENV", "testing")

latest_url_with_token = None

code_store: Dict[str, List[Dict[str, Any]]] = {}


class CustomPlessEmailService(
    passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: passwordless.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        codes = code_store.get(template_vars.pre_auth_session_id)
        if codes is None:
            codes = []
        if template_vars.url_with_link_code:
            template_vars.url_with_link_code = template_vars.url_with_link_code.replace(
                "?preAuthSessionId", "?test=fix&preAuthSessionId"
            )
        codes.append(
            {
                "urlWithLinkCode": template_vars.url_with_link_code,
                "userInputCode": template_vars.user_input_code,
            }
        )
        code_store[template_vars.pre_auth_session_id] = codes


class CustomSMSService(passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]):
    async def send_sms(
        self, template_vars: passwordless.SMSTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        codes = code_store.get(template_vars.pre_auth_session_id)
        if codes is None:
            codes = []
        if template_vars.url_with_link_code:
            template_vars.url_with_link_code = template_vars.url_with_link_code.replace(
                "?preAuthSessionId", "?test=fix&preAuthSessionId"
            )
        codes.append(
            {
                "urlWithLinkCode": template_vars.url_with_link_code,
                "userInputCode": template_vars.user_input_code,
            }
        )
        code_store[template_vars.pre_auth_session_id] = codes


class CustomEVEmailService(
    emailverification.EmailDeliveryInterface[emailverification.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: emailverification.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        global latest_url_with_token
        latest_url_with_token = template_vars.email_verify_link


class CustomEPEmailService(
    emailpassword.EmailDeliveryInterface[emailpassword.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: emailpassword.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        global latest_url_with_token
        latest_url_with_token = template_vars.password_reset_link


async def create_and_send_custom_email(
    _: User, url_with_token: str, __: Dict[str, Any]
) -> None:
    global latest_url_with_token
    latest_url_with_token = url_with_token


async def validate_age(value: Any, _tenant_id: str):
    try:
        if int(value) < 18:
            return "You must be over 18 to register"
    except Exception:
        pass

    return None


form_fields = [
    InputFormField("name"),
    InputFormField("age", validate=validate_age),
    InputFormField("country", optional=True),
]


async def check_request_body_for_general_error(req: BaseRequest) -> bool:
    body = await req.json()
    return body is not None and "generalError" in body and body["generalError"]


def check_request_query_for_general_error(req: BaseRequest) -> bool:
    general_error = req.get_query_param("generalError")
    return general_error is not None and general_error == "true"


async def check_for_general_error(
    check_from: Literal["query", "body"], req: BaseRequest
):
    is_general_error = False
    if check_from == "query":
        is_general_error = check_request_query_for_general_error(req)
    else:
        is_general_error = await check_request_body_for_general_error(req)

    return is_general_error


from supertokens_python.recipe.thirdparty.types import UserInfo, UserInfoEmail


def auth0_provider_override(oi: Provider) -> Provider:
    async def get_user_info(  # pylint: disable=no-self-use
        oauth_tokens: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> UserInfo:
        access_token = oauth_tokens.get("access_token")
        if access_token is None:
            raise Exception("access token is undefined")

        return UserInfo(
            "someId",
            UserInfoEmail("test@example.com", True),
        )

    oi.get_user_info = get_user_info
    return oi


def custom_init(
    contact_method: Union[None, Literal["PHONE", "EMAIL", "EMAIL_OR_PHONE"]] = None,
    flow_type: Union[
        None, Literal["USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"]
    ] = None,
):
    UserRolesRecipe.reset()
    PasswordlessRecipe.reset()
    JWTRecipe.reset()
    EmailVerificationRecipe.reset()
    SessionRecipe.reset()
    ThirdPartyRecipe.reset()
    EmailPasswordRecipe.reset()
    EmailVerificationRecipe.reset()
    DashboardRecipe.reset()
    MultitenancyRecipe.reset()
    Supertokens.reset()

    def override_email_verification_apis(
        original_implementation_email_verification: EmailVerificationAPIInterface,
    ):
        original_email_verify_post = (
            original_implementation_email_verification.email_verify_post
        )
        original_generate_email_verify_token_post = (
            original_implementation_email_verification.generate_email_verify_token_post
        )

        async def email_verify_post(
            token: str,
            session: Optional[SessionContainer],
            tenant_id: str,
            api_options: EVAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API email verify")
            return await original_email_verify_post(
                token,
                session,
                tenant_id,
                api_options,
                user_context,
            )

        async def generate_email_verify_token_post(
            session: SessionContainer,
            api_options: EVAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse(
                    "general error from API email verification code"
                )
            return await original_generate_email_verify_token_post(
                session, api_options, user_context
            )

        original_implementation_email_verification.email_verify_post = email_verify_post
        original_implementation_email_verification.generate_email_verify_token_post = (
            generate_email_verify_token_post
        )
        return original_implementation_email_verification

    def override_email_password_apis(
        original_implementation: EmailPasswordAPIInterface,
    ):
        original_email_exists_get = original_implementation.email_exists_get
        original_generate_password_reset_token_post = (
            original_implementation.generate_password_reset_token_post
        )
        original_password_reset_post = original_implementation.password_reset_post
        original_sign_in_post = original_implementation.sign_in_post
        original_sign_up_post = original_implementation.sign_up_post

        async def email_exists_get(
            email: str,
            tenant_id: str,
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "query", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API email exists")
            return await original_email_exists_get(
                email, tenant_id, api_options, user_context
            )

        async def generate_password_reset_token_post(
            form_fields: List[FormField],
            tenant_id: str,
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API reset password")
            return await original_generate_password_reset_token_post(
                form_fields, tenant_id, api_options, user_context
            )

        async def password_reset_post(
            form_fields: List[FormField],
            token: str,
            tenant_id: str,
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse(
                    "general error from API reset password consume"
                )
            return await original_password_reset_post(
                form_fields, token, tenant_id, api_options, user_context
            )

        async def sign_in_post(
            form_fields: List[FormField],
            tenant_id: str,
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                msg = "general error from API sign in"
                body = await api_options.request.json()
                if body is not None and "generalErrorMessage" in body:
                    msg = body["generalErrorMessage"]
                return GeneralErrorResponse(msg)
            return await original_sign_in_post(
                form_fields, tenant_id, api_options, user_context
            )

        async def sign_up_post(
            form_fields: List[FormField],
            tenant_id: str,
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign up")
            return await original_sign_up_post(
                form_fields, tenant_id, api_options, user_context
            )

        original_implementation.email_exists_get = email_exists_get
        original_implementation.generate_password_reset_token_post = (
            generate_password_reset_token_post
        )
        original_implementation.password_reset_post = password_reset_post
        original_implementation.sign_in_post = sign_in_post
        original_implementation.sign_up_post = sign_up_post
        return original_implementation

    def override_thirdparty_apis(original_implementation: ThirdpartyAPIInterface):
        original_sign_in_up_post = original_implementation.sign_in_up_post
        original_authorisation_url_get = original_implementation.authorisation_url_get

        async def sign_in_up_post(
            provider: Provider,
            redirect_uri_info: Union[RedirectUriInfo, None],
            oauth_tokens: Union[Dict[str, Any], None],
            tenant_id: str,
            api_options: TPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign in up")
            return await original_sign_in_up_post(
                provider,
                redirect_uri_info,
                oauth_tokens,
                tenant_id,
                api_options,
                user_context,
            )

        async def authorisation_url_get(
            provider: Provider,
            redirect_uri_on_provider_dashboard: str,
            api_options: TPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "query", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse(
                    "general error from API authorisation url get"
                )
            return await original_authorisation_url_get(
                provider, redirect_uri_on_provider_dashboard, api_options, user_context
            )

        original_implementation.sign_in_up_post = sign_in_up_post
        original_implementation.authorisation_url_get = authorisation_url_get
        return original_implementation

    def override_session_apis(original_implementation: SessionAPIInterface):
        original_signout_post = original_implementation.signout_post

        async def signout_post(
            session: Optional[SessionContainer],
            api_options: SAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from signout API")
            return await original_signout_post(session, api_options, user_context)

        original_implementation.signout_post = signout_post
        return original_implementation

    def override_passwordless_apis(original_implementation: PasswordlessAPIInterface):
        original_consume_code_post = original_implementation.consume_code_post
        original_create_code_post = original_implementation.create_code_post
        original_resend_code_post = original_implementation.resend_code_post

        async def consume_code_post(
            pre_auth_session_id: str,
            user_input_code: Union[str, None],
            device_id: Union[str, None],
            link_code: Union[str, None],
            tenant_id: str,
            api_options: PAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API consume code")
            return await original_consume_code_post(
                pre_auth_session_id,
                user_input_code,
                device_id,
                link_code,
                tenant_id,
                api_options,
                user_context,
            )

        async def create_code_post(
            email: Union[str, None],
            phone_number: Union[str, None],
            tenant_id: str,
            api_options: PAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API create code")
            return await original_create_code_post(
                email, phone_number, tenant_id, api_options, user_context
            )

        async def resend_code_post(
            device_id: str,
            pre_auth_session_id: str,
            tenant_id: str,
            api_options: PAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API resend code")
            return await original_resend_code_post(
                device_id, pre_auth_session_id, tenant_id, api_options, user_context
            )

        original_implementation.consume_code_post = consume_code_post
        original_implementation.create_code_post = create_code_post
        original_implementation.resend_code_post = resend_code_post
        return original_implementation

    providers_list: List[thirdparty.ProviderInput] = [
        thirdparty.ProviderInput(
            config=thirdparty.ProviderConfig(
                third_party_id="google",
                clients=[
                    thirdparty.ProviderClientConfig(
                        client_id=os.environ["GOOGLE_CLIENT_ID"],
                        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
                    ),
                ],
            ),
        ),
        thirdparty.ProviderInput(
            config=thirdparty.ProviderConfig(
                third_party_id="github",
                clients=[
                    thirdparty.ProviderClientConfig(
                        client_id=os.environ["GITHUB_CLIENT_ID"],
                        client_secret=os.environ["GITHUB_CLIENT_SECRET"],
                    ),
                ],
            )
        ),
        thirdparty.ProviderInput(
            config=thirdparty.ProviderConfig(
                third_party_id="auth0",
                name="Auth0",
                authorization_endpoint=f"https://{os.environ['AUTH0_DOMAIN']}/authorize",
                authorization_endpoint_query_params={"scope": "openid profile"},
                token_endpoint=f"https://{os.environ['AUTH0_DOMAIN']}/oauth/token",
                clients=[
                    thirdparty.ProviderClientConfig(
                        client_id=os.environ["AUTH0_CLIENT_ID"],
                        client_secret=os.environ["AUTH0_CLIENT_SECRET"],
                    )
                ],
            ),
            override=auth0_provider_override,
        ),
    ]

    if contact_method is not None and flow_type is not None:
        if contact_method == "PHONE":
            passwordless_init = passwordless.init(
                contact_config=ContactPhoneOnlyConfig(),
                flow_type=flow_type,
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
                override=passwordless.InputOverrideConfig(
                    apis=override_passwordless_apis
                ),
            )
        elif contact_method == "EMAIL":
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOnlyConfig(),
                flow_type=flow_type,
                email_delivery=passwordless.EmailDeliveryConfig(
                    CustomPlessEmailService()
                ),
                override=passwordless.InputOverrideConfig(
                    apis=override_passwordless_apis
                ),
            )
        else:
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOrPhoneConfig(),
                flow_type=flow_type,
                email_delivery=passwordless.EmailDeliveryConfig(
                    CustomPlessEmailService()
                ),
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
                override=passwordless.InputOverrideConfig(
                    apis=override_passwordless_apis
                ),
            )
    else:
        passwordless_init = passwordless.init(
            contact_config=ContactEmailOrPhoneConfig(),
            flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            email_delivery=passwordless.EmailDeliveryConfig(CustomPlessEmailService()),
            sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
            override=passwordless.InputOverrideConfig(apis=override_passwordless_apis),
        )

    recipe_list = [
        userroles.init(),
        session.init(override=session.InputOverrideConfig(apis=override_session_apis)),
        emailverification.init(
            mode="OPTIONAL",
            email_delivery=emailverification.EmailDeliveryConfig(
                CustomEVEmailService()
            ),
            override=EVInputOverrideConfig(apis=override_email_verification_apis),
        ),
        emailpassword.init(
            sign_up_feature=emailpassword.InputSignUpFeature(form_fields),
            email_delivery=emailpassword.EmailDeliveryConfig(CustomEPEmailService()),
            override=emailpassword.InputOverrideConfig(
                apis=override_email_password_apis,
            ),
        ),
        thirdparty.init(
            sign_in_and_up_feature=thirdparty.SignInAndUpFeature(providers_list),
            override=thirdparty.InputOverrideConfig(apis=override_thirdparty_apis),
        ),
        passwordless_init,
    ]

    init(
        supertokens_config=SupertokensConfig("http://localhost:9000"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="0.0.0.0:" + get_api_port(),
            website_domain=get_website_domain(),
        ),
        framework="flask",
        recipe_list=recipe_list,
        telemetry=False,
    )


custom_init()


def make_default_options_response():
    _response = make_response()
    _response.status_code = 204
    return _response


app = Flask(__name__, template_folder="templates")
app.make_default_options_response = make_default_options_response
Middleware(app)
CORS(
    app=app,
    supports_credentials=True,
    origins=get_website_domain(),
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)


@app.route("/ping", methods=["GET"])  # type: ignore
def ping():
    return "success"


@app.route("/sessionInfo", methods=["GET"])  # type: ignore
@verify_session()
def get_session_info():
    session_ = g.supertokens
    return jsonify(
        {
            "sessionHandle": session_.get_handle(),
            "userId": session_.get_user_id(),
            "accessTokenPayload": session_.get_access_token_payload(),
            "sessionDataFromDatabase": session_.sync_get_session_data_from_database(),
        }
    )


@app.route("/token", methods=["GET"])  # type: ignore
def get_token():
    global latest_url_with_token
    return jsonify({"latestURLWithToken": latest_url_with_token})


@app.route("/beforeeach", methods=["POST"])  # type: ignore
def before_each():
    global code_store
    code_store = dict()
    return ""


@app.route("/test/setFlow", methods=["POST"])  # type: ignore
def test_set_flow():
    body: Union[Any, None] = request.get_json()
    if body is None:
        raise Exception("Should never come here")
    contact_method = body["contactMethod"]
    flow_type = body["flowType"]
    custom_init(contact_method=contact_method, flow_type=flow_type)
    return ""


@app.get("/test/getDevice")  # type: ignore
def test_get_device():
    global code_store
    pre_auth_session_id = request.args.get("preAuthSessionId")
    if pre_auth_session_id is None:
        return ""
    codes = code_store.get(pre_auth_session_id)
    return jsonify({"preAuthSessionId": pre_auth_session_id, "codes": codes})


@app.get("/test/featureFlags")  # type: ignore
def test_feature_flags():
    available = ["passwordless", "thirdpartypasswordless", "generalerror", "userroles"]
    return jsonify({"available": available})


@app.get("/unverifyEmail")  # type: ignore
@verify_session()
def unverify_email_api():
    session_: SessionContainer = g.supertokens  # type: ignore
    unverify_email(session_.get_user_id())
    session_.sync_fetch_and_set_claim(EmailVerificationClaim)
    return jsonify({"status": "OK"})


@app.route("/setRole", methods=["POST"])  # type: ignore
@verify_session()
def verify_email_api():
    session_: SessionContainer = g.supertokens  # type: ignore
    body: Dict[str, Any] = request.get_json()  # type: ignore
    create_new_role_or_add_permissions(body["role"], body["permissions"])
    add_role_to_user("public", session_.get_user_id(), body["role"])
    session_.sync_fetch_and_set_claim(UserRoleClaim)
    session_.sync_fetch_and_set_claim(PermissionClaim)
    return jsonify({"status": "OK"})


@app.route("/deleteUser", methods=["POST"])  # type: ignore
def delete_user_api():
    body: Dict[str, Any] = request.get_json()  # type: ignore
    user = get_user_by_email("public", body["email"])
    if user is None:
        raise Exception("Should not come here")
    delete_user(user.user_id)
    return jsonify({"status": "OK"})


async def override_global_claim_validators(
    gv: List[SessionClaimValidator],
    _session: SessionContainer,
    user_context: Dict[str, Any],
):
    validators = gv.copy()
    req = user_context["_default"]["request"]
    body = await req.json()

    if body.get("role"):
        info = body["role"]
        validator = getattr(UserRoleClaim.validators, info["validator"])
        validators.append(validator(*info["args"]))

    if body.get("permission"):
        info = body["permission"]
        validator = getattr(PermissionClaim.validators, info["validator"])
        validators.append(validator(*info["args"]))

    return validators


@app.route("/checkRole", methods=["POST"])  # type: ignore
@verify_session(override_global_claim_validators=override_global_claim_validators)
def check_role_api():
    return jsonify({"status": "OK"})


@app.route("/", defaults={"path": ""})  # type: ignore
@app.route("/<path:path>")  # type: ignore
def index(_: str):
    return ""


@app.errorhandler(Exception)  # type: ignore
def all_exception_handler(e: Exception):
    return "Error", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(get_api_port()), threaded=True)
