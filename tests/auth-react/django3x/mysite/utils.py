import os
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

import requests
from dotenv import load_dotenv
from supertokens_python import InputAppInfo, Supertokens, SupertokensConfig, init
from supertokens_python.framework.request import BaseRequest
from supertokens_python.recipe import (
    accountlinking,
    emailpassword,
    emailverification,
    multifactorauth,
    multitenancy,
    oauth2provider,
    passwordless,
    session,
    thirdparty,
    totp,
    userroles,
)
from supertokens_python.recipe.accountlinking import AccountInfoWithRecipeIdAndUserId
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.dashboard import DashboardRecipe
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface as EmailPasswordAPIInterface,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    APIOptions as EPAPIOptions,
)
from supertokens_python.recipe.emailpassword.types import (
    FormField,
    InputFormField,
)
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.emailverification import (
    InputOverrideConfig as EVInputOverrideConfig,
)
from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface as EmailVerificationAPIInterface,
)
from supertokens_python.recipe.emailverification.interfaces import (
    APIOptions as EVAPIOptions,
)
from supertokens_python.recipe.jwt import JWTRecipe
from supertokens_python.recipe.multifactorauth.interfaces import (
    ResyncSessionAndFetchMFAInfoPUTOkResult,
)
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multifactorauth.types import MFARequirementList
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.passwordless import (
    ContactEmailOnlyConfig,
    ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig,
    CreateAndSendCustomEmailParameters,
    CreateAndSendCustomTextMessageParameters,
    PasswordlessRecipe,
)
from supertokens_python.recipe.passwordless.interfaces import (
    APIInterface as PasswordlessAPIInterface,
)
from supertokens_python.recipe.passwordless.interfaces import APIOptions as PAPIOptions
from supertokens_python.recipe.session import SessionContainer, SessionRecipe
from supertokens_python.recipe.session.exceptions import (
    ClaimValidationError,
    InvalidClaimsError,
)
from supertokens_python.recipe.session.interfaces import (
    APIInterface as SessionAPIInterface,
)
from supertokens_python.recipe.session.interfaces import APIOptions as SAPIOptions
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.interfaces import (
    APIInterface as ThirdpartyAPIInterface,
)
from supertokens_python.recipe.thirdparty.interfaces import APIOptions as TPAPIOptions
from supertokens_python.recipe.thirdparty.provider import Provider, RedirectUriInfo
from supertokens_python.recipe.thirdparty.types import UserInfo, UserInfoEmail
from supertokens_python.recipe.totp.recipe import TOTPRecipe
from supertokens_python.recipe.userroles import UserRolesRecipe
from supertokens_python.types import GeneralErrorResponse, User
from typing_extensions import Literal

from .store import save_code, save_url_with_token

load_dotenv("../auth-react.env")


def get_api_port():
    return "8083"


def get_website_port():
    return "3031"


def get_website_domain():
    return "http://localhost:" + get_website_port()


async def save_code_email(param: CreateAndSendCustomEmailParameters, _: Dict[str, Any]):
    save_code(
        param.pre_auth_session_id, param.url_with_link_code, param.user_input_code
    )


async def save_code_text(
    param: CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]
):
    save_code(
        param.pre_auth_session_id, param.url_with_link_code, param.user_input_code
    )


class CustomPlessEmailService(
    passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: passwordless.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        save_code(
            template_vars.pre_auth_session_id,
            template_vars.url_with_link_code,
            template_vars.user_input_code,
        )


class CustomSMSService(passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]):
    async def send_sms(
        self, template_vars: passwordless.SMSTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        save_code(
            template_vars.pre_auth_session_id,
            template_vars.url_with_link_code,
            template_vars.user_input_code,
        )


class CustomEVEmailService(
    emailverification.EmailDeliveryInterface[emailverification.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: emailverification.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        save_url_with_token(template_vars.email_verify_link)


class CustomEPEmailService(
    emailpassword.EmailDeliveryInterface[emailpassword.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: emailpassword.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        save_url_with_token(template_vars.password_reset_link)


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


def auth0_provider_override(oi: Provider) -> Provider:
    async def get_user_info(
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
            third_party_id="facebook",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id=os.environ["FACEBOOK_CLIENT_ID"],
                    client_secret=os.environ["FACEBOOK_CLIENT_SECRET"],
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


def mock_provider_override(oi: Provider) -> Provider:
    async def get_user_info(
        oauth_tokens: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> UserInfo:
        user_id = oauth_tokens.get("userId", "user")
        email = oauth_tokens.get("email", "email@test.com")
        is_verified = oauth_tokens.get("isVerified", "true").lower() != "false"

        return UserInfo(
            user_id, UserInfoEmail(email, is_verified), raw_user_info_from_provider=None
        )

    async def exchange_auth_code_for_oauth_tokens(
        redirect_uri_info: RedirectUriInfo,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        return redirect_uri_info.redirect_uri_query_params

    oi.exchange_auth_code_for_oauth_tokens = exchange_auth_code_for_oauth_tokens
    oi.get_user_info = get_user_info
    return oi


def get_core_url():
    host = os.environ.get("SUPERTOKENS_CORE_HOST", "localhost")
    port = os.environ.get("SUPERTOKENS_CORE_PORT", "3567")

    return f"http://{host}:{port}"


def setup_core_app(
    *, appId: Optional[str] = None, coreConfig: Optional[Dict[str, Any]] = None
):
    core_url = get_core_url()

    if appId is None:
        appId = ""

    if coreConfig is None:
        coreConfig = {}

    response = requests.put(
        f"{core_url}/recipe/multitenancy/app/v2",
        headers={
            "Content-Type": "application/json",
        },
        data={
            "appId": appId,
            "coreConfig": coreConfig,
        },
    )

    response_body = response.json()
    assert response_body["status"] == "OK"

    return f"{core_url}/appid-{appId}"


def custom_init(
    *,
    coreUrl: str = get_core_url(),
    accountLinkingConfig: Optional[Dict[str, Any]] = None,
    enabledRecipes: Optional[List[str]] = None,
    enabledProviders: Optional[List[str]] = None,
    passwordlessFlowType: Optional[str] = "USER_INPUT_CODE_AND_MAGIC_LINK",
    passwordlessContactMethod: Optional[str] = "EMAIL_OR_PHONE",
    mfaInfo: Optional[Dict[str, Any]] = None,
):
    if accountLinkingConfig is None:
        accountLinkingConfig = {}

    if mfaInfo is None:
        mfaInfo = {}

    AccountLinkingRecipe.reset()
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
    TOTPRecipe.reset()
    MultiFactorAuthRecipe.reset()
    OpenIdRecipe.reset()
    OAuth2ProviderRecipe.reset()

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
            session: Optional[SessionContainer],
            should_try_linking_with_session_user: Union[bool, None],
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
                form_fields,
                tenant_id,
                session,
                should_try_linking_with_session_user,
                api_options,
                user_context,
            )

        async def sign_up_post(
            form_fields: List[FormField],
            tenant_id: str,
            session: Optional[SessionContainer],
            should_try_linking_with_session_user: Union[bool, None],
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign up")
            return await original_sign_up_post(
                form_fields,
                tenant_id,
                session,
                should_try_linking_with_session_user,
                api_options,
                user_context,
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
            session: Optional[SessionContainer],
            should_try_linking_with_session_user: Union[bool, None],
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
                session,
                should_try_linking_with_session_user,
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
            session: SessionContainer,
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
            session: Optional[SessionContainer],
            should_try_linking_with_session_user: Union[bool, None],
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
                session,
                should_try_linking_with_session_user,
                tenant_id,
                api_options,
                user_context,
            )

        async def create_code_post(
            email: Union[str, None],
            phone_number: Union[str, None],
            session: Optional[SessionContainer],
            should_try_linking_with_session_user: Union[bool, None],
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
                email,
                phone_number,
                session,
                should_try_linking_with_session_user,
                tenant_id,
                api_options,
                user_context,
            )

        async def resend_code_post(
            device_id: str,
            pre_auth_session_id: str,
            session: Optional[SessionContainer],
            should_try_linking_with_session_user: Union[bool, None],
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
                device_id,
                pre_auth_session_id,
                session,
                should_try_linking_with_session_user,
                tenant_id,
                api_options,
                user_context,
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
                third_party_id="facebook",
                clients=[
                    thirdparty.ProviderClientConfig(
                        client_id=os.environ["FACEBOOK_CLIENT_ID"],
                        client_secret=os.environ["FACEBOOK_CLIENT_SECRET"],
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
        thirdparty.ProviderInput(
            config=thirdparty.ProviderConfig(
                third_party_id="mock-provider",
                name="Mock Provider",
                authorization_endpoint=get_website_domain() + "/mockProvider/auth",
                token_endpoint=get_website_domain() + "/mockProvider/token",
                clients=[
                    thirdparty.ProviderClientConfig(
                        client_id="supertokens",
                        client_secret="",
                    )
                ],
            ),
            override=mock_provider_override,
        ),
    ]

    if enabledProviders is not None:
        providers_list = [
            provider
            for provider in providers_list
            if provider.config.third_party_id in enabledProviders
        ]

    if passwordlessContactMethod is not None and passwordlessFlowType is not None:
        if passwordlessContactMethod == "PHONE":
            passwordless_init = passwordless.init(
                contact_config=ContactPhoneOnlyConfig(),
                flow_type=passwordlessFlowType,  # type: ignore - type expects only certain literals
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
                override=passwordless.InputOverrideConfig(
                    apis=override_passwordless_apis
                ),
            )
        elif passwordlessContactMethod == "EMAIL":
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOnlyConfig(),
                flow_type=passwordlessFlowType,  # type: ignore - type expects only certain literals
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
                flow_type=passwordlessFlowType,  # type: ignore - type expects only certain literals
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

    async def get_allowed_domains_for_tenant_id(
        tenant_id: str, _: Dict[str, Any]
    ) -> List[str]:
        return [tenant_id + ".example.com", "localhost"]

    from supertokens_python.recipe.multifactorauth.interfaces import (
        APIInterface as MFAApiInterface,
    )
    from supertokens_python.recipe.multifactorauth.interfaces import (
        APIOptions as MFAApiOptions,
    )
    from supertokens_python.recipe.multifactorauth.interfaces import (
        RecipeInterface as MFARecipeInterface,
    )

    def override_mfa_functions(original_implementation: MFARecipeInterface):
        og_get_factors_setup_for_user = (
            original_implementation.get_factors_setup_for_user
        )

        async def get_factors_setup_for_user(
            user: User,
            user_context: Dict[str, Any],
        ):
            res = await og_get_factors_setup_for_user(user, user_context)
            if "alreadySetup" in mfaInfo:
                return mfaInfo["alreadySetup"]
            return res

        og_assert_allowed_to_setup_factor = original_implementation.assert_allowed_to_setup_factor_else_throw_invalid_claim_error

        async def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
            session: SessionContainer,
            factor_id: str,
            mfa_requirements_for_auth: Callable[[], Awaitable[MFARequirementList]],
            factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
            user_context: Dict[str, Any],
        ):
            if "allowedToSetup" in mfaInfo:
                if factor_id not in mfaInfo["allowedToSetup"]:
                    raise InvalidClaimsError(
                        msg="INVALID_CLAIMS",
                        payload=[
                            ClaimValidationError(id_="test", reason="test override")
                        ],
                    )
            else:
                await og_assert_allowed_to_setup_factor(
                    session,
                    factor_id,
                    mfa_requirements_for_auth,
                    factors_set_up_for_user,
                    user_context,
                )

        og_get_mfa_requirements_for_auth = (
            original_implementation.get_mfa_requirements_for_auth
        )

        async def get_mfa_requirements_for_auth(
            tenant_id: str,
            access_token_payload: Dict[str, Any],
            completed_factors: Dict[str, int],
            user: Callable[[], Awaitable[User]],
            factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
            required_secondary_factors_for_user: Callable[[], Awaitable[List[str]]],
            required_secondary_factors_for_tenant: Callable[[], Awaitable[List[str]]],
            user_context: Dict[str, Any],
        ) -> MFARequirementList:
            res = await og_get_mfa_requirements_for_auth(
                tenant_id,
                access_token_payload,
                completed_factors,
                user,
                factors_set_up_for_user,
                required_secondary_factors_for_user,
                required_secondary_factors_for_tenant,
                user_context,
            )
            if "requirements" in mfaInfo:
                return mfaInfo["requirements"]
            return res

        original_implementation.get_mfa_requirements_for_auth = (
            get_mfa_requirements_for_auth
        )

        original_implementation.assert_allowed_to_setup_factor_else_throw_invalid_claim_error = assert_allowed_to_setup_factor_else_throw_invalid_claim_error

        original_implementation.get_factors_setup_for_user = get_factors_setup_for_user
        return original_implementation

    def override_mfa_apis(original_implementation: MFAApiInterface):
        og_resync_session_and_fetch_mfa_info_put = (
            original_implementation.resync_session_and_fetch_mfa_info_put
        )

        async def resync_session_and_fetch_mfa_info_put(
            api_options: MFAApiOptions,
            session: SessionContainer,
            user_context: Dict[str, Any],
        ) -> Union[ResyncSessionAndFetchMFAInfoPUTOkResult, GeneralErrorResponse]:
            res = await og_resync_session_and_fetch_mfa_info_put(
                api_options, session, user_context
            )

            if isinstance(res, ResyncSessionAndFetchMFAInfoPUTOkResult):
                if "alreadySetup" in mfaInfo:
                    res.factors.already_setup = mfaInfo["alreadySetup"][:]

                if "noContacts" in mfaInfo:
                    res.emails = {}
                    res.phone_numbers = {}

            return res

        original_implementation.resync_session_and_fetch_mfa_info_put = (
            resync_session_and_fetch_mfa_info_put
        )
        return original_implementation

    recipe_list: List[Any] = [
        {"id": "userroles", "init": userroles.init()},
        {
            "id": "session",
            "init": session.init(
                override=session.InputOverrideConfig(apis=override_session_apis)
            ),
        },
        {
            "id": "emailverification",
            "init": emailverification.init(
                mode="OPTIONAL",
                email_delivery=emailverification.EmailDeliveryConfig(
                    CustomEVEmailService()
                ),
                override=EVInputOverrideConfig(apis=override_email_verification_apis),
            ),
        },
        {
            "id": "emailpassword",
            "init": emailpassword.init(
                sign_up_feature=emailpassword.InputSignUpFeature(form_fields),
                email_delivery=emailpassword.EmailDeliveryConfig(
                    CustomEPEmailService()
                ),
                override=emailpassword.InputOverrideConfig(
                    apis=override_email_password_apis,
                ),
            ),
        },
        {
            "id": "thirdparty",
            "init": thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(providers_list),
                override=thirdparty.InputOverrideConfig(apis=override_thirdparty_apis),
            ),
        },
        {
            "id": "passwordless",
            "init": passwordless_init,
        },
        {
            "id": "multitenancy",
            "init": multitenancy.init(
                get_allowed_domains_for_tenant_id=get_allowed_domains_for_tenant_id
            ),
        },
        {
            "id": "multifactorauth",
            "init": multifactorauth.init(
                first_factors=mfaInfo.get("firstFactors", None),
                override=multifactorauth.OverrideConfig(
                    functions=override_mfa_functions,
                    apis=override_mfa_apis,
                ),
            ),
        },
        {
            "id": "totp",
            "init": totp.init(
                config=totp.TOTPConfig(
                    default_period=1,
                    default_skew=30,
                )
            ),
        },
        {
            "id": "oauth2provider",
            "init": oauth2provider.init(),
        },
    ]

    accountlinking_config_input: Dict[str, Any] = {
        "enabled": False,
        "shouldAutoLink": {
            "shouldAutomaticallyLink": True,
            "shouldRequireVerification": True,
        },
        **accountLinkingConfig,
    }

    async def should_do_automatic_account_linking(
        _: AccountInfoWithRecipeIdAndUserId,
        __: Optional[User],
        ___: Optional[SessionContainer],
        ____: str,
        _____: Dict[str, Any],
    ) -> Union[
        accountlinking.ShouldNotAutomaticallyLink,
        accountlinking.ShouldAutomaticallyLink,
    ]:
        should_auto_link = accountlinking_config_input["shouldAutoLink"]
        assert isinstance(should_auto_link, dict)
        should_automatically_link = should_auto_link["shouldAutomaticallyLink"]  # type: ignore
        assert isinstance(should_automatically_link, bool)
        if should_automatically_link:
            should_require_verification = should_auto_link["shouldRequireVerification"]  # type: ignore
            assert isinstance(should_require_verification, bool)
            return accountlinking.ShouldAutomaticallyLink(
                should_require_verification=should_require_verification
            )
        return accountlinking.ShouldNotAutomaticallyLink()

    if accountlinking_config_input["enabled"]:
        recipe_list.append(
            {
                "id": "accountlinking",
                "init": accountlinking.init(
                    should_do_automatic_account_linking=should_do_automatic_account_linking
                ),
            }
        )

    if enabledRecipes is not None:
        new_recipe_list = []
        for item in recipe_list:
            for recipe_id in enabledRecipes:
                if item["id"] in recipe_id:
                    new_recipe_list.append(item["init"])  # type: ignore
                    break

        recipe_list = new_recipe_list

    else:
        recipe_list = [item["init"] for item in recipe_list]

    init(
        supertokens_config=SupertokensConfig(coreUrl),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="localhost:" + get_api_port(),
            website_domain=get_website_domain(),
        ),
        framework="django",
        mode=os.environ.get("APP_MODE", "asgi"),  # type: ignore
        recipe_list=recipe_list,
        telemetry=False,
    )
