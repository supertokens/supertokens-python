import os
from typing import Any, Dict, List, Optional, Union

from dotenv import load_dotenv
from typing_extensions import Literal

from supertokens_python import InputAppInfo, Supertokens, SupertokensConfig, init
from supertokens_python.framework.request import BaseRequest
from supertokens_python.recipe import (
    emailpassword,
    emailverification,
    passwordless,
    session,
    thirdparty,
    thirdpartyemailpassword,
    thirdpartypasswordless,
    userroles,
)
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
    User,
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
from supertokens_python.recipe.emailverification.types import User as EVUser
from supertokens_python.recipe.jwt import JWTRecipe
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
from supertokens_python.recipe.thirdpartyemailpassword import (
    ThirdPartyEmailPasswordRecipe,
)
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import (
    APIInterface as ThirdpartyEmailPasswordAPIInterface,
)
from supertokens_python.recipe.thirdpartypasswordless import (
    ThirdPartyPasswordlessRecipe,
)
from supertokens_python.recipe.thirdpartypasswordless.interfaces import (
    APIInterface as ThirdpartyPasswordlessAPIInterface,
)
from supertokens_python.recipe.userroles import UserRolesRecipe
from supertokens_python.types import GeneralErrorResponse

from .store import save_code, save_url_with_token

load_dotenv()


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


async def ev_create_and_send_custom_email(
    _: EVUser, url_with_token: str, __: Dict[str, Any]
):
    save_url_with_token(url_with_token)


async def create_and_send_custom_email(
    _: User, url_with_token: str, __: Dict[str, Any]
):
    save_url_with_token(url_with_token)


async def validate_age(value: Any):
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


def auth0_provider_override(provider: Provider) -> Provider:
    # TODO: Finish when Node SDK is ready
    return provider


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
            third_party_id="facebook",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id=os.environ["FACEBOOK_CLIENT_ID"],
                    client_secret=os.environ["FACEBOOK_CLIENT_SECRET"],
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
            third_party_id="custom",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id=os.environ["DISCORD_CLIENT_ID"],
                    client_secret=os.environ["DISCORD_CLIENT_SECRET"],
                ),
            ],
        )
    ),
    thirdparty.ProviderInput(
        config=thirdparty.ProviderConfig(
            third_party_id="auth0",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id=os.environ["AUTH0_CLIENT_ID"],
                    client_secret=os.environ["AUTH0_CLIENT_SECRET"],
                    additional_config={"domain": os.environ["AUTH0_DOMAIN"]},
                )
            ],
        ),
        override=auth0_provider_override,
    ),
]


def custom_init(
    contact_method: Union[None, Literal["PHONE", "EMAIL", "EMAIL_OR_PHONE"]] = None,
    flow_type: Union[
        None, Literal["USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"]
    ] = None,
):
    UserRolesRecipe.reset()
    PasswordlessRecipe.reset()
    ThirdPartyPasswordlessRecipe.reset()
    JWTRecipe.reset()
    EmailVerificationRecipe.reset()
    SessionRecipe.reset()
    ThirdPartyRecipe.reset()
    EmailPasswordRecipe.reset()
    EmailVerificationRecipe.reset()
    ThirdPartyEmailPasswordRecipe.reset()
    DashboardRecipe.reset()
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
            email: str, api_options: EPAPIOptions, user_context: Dict[str, Any]
        ):
            is_general_error = await check_for_general_error(
                "query", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API email exists")
            return await original_email_exists_get(email, api_options, user_context)

        async def generate_password_reset_token_post(
            form_fields: List[FormField],
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API reset password")
            return await original_generate_password_reset_token_post(
                form_fields, api_options, user_context
            )

        async def password_reset_post(
            form_fields: List[FormField],
            token: str,
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
                form_fields, token, api_options, user_context
            )

        async def sign_in_post(
            form_fields: List[FormField],
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
            return await original_sign_in_post(form_fields, api_options, user_context)

        async def sign_up_post(
            form_fields: List[FormField],
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign up")
            return await original_sign_up_post(form_fields, api_options, user_context)

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

    def override_thirdpartyemailpassword_apis(
        original_implementation: ThirdpartyEmailPasswordAPIInterface,
    ):
        original_emailpassword_email_exists_get = (
            original_implementation.emailpassword_email_exists_get
        )
        original_generate_password_reset_token_post = (
            original_implementation.generate_password_reset_token_post
        )
        original_password_reset_post = original_implementation.password_reset_post
        original_emailpassword_sign_in_post = (
            original_implementation.emailpassword_sign_in_post
        )
        original_emailpassword_sign_up_post = (
            original_implementation.emailpassword_sign_up_post
        )
        original_thirdparty_sign_in_up_post = (
            original_implementation.thirdparty_sign_in_up_post
        )
        original_authorisation_url_get = original_implementation.authorisation_url_get

        async def emailpassword_email_exists_get(
            email: str, api_options: EPAPIOptions, user_context: Dict[str, Any]
        ):
            is_general_error = await check_for_general_error(
                "query", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API email exists")
            return await original_emailpassword_email_exists_get(
                email, api_options, user_context
            )

        async def generate_password_reset_token_post(
            form_fields: List[FormField],
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API reset password")
            return await original_generate_password_reset_token_post(
                form_fields, api_options, user_context
            )

        async def password_reset_post(
            form_fields: List[FormField],
            token: str,
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
                form_fields, token, api_options, user_context
            )

        async def emailpassword_sign_in_post(
            form_fields: List[FormField],
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign in")
            return await original_emailpassword_sign_in_post(
                form_fields, api_options, user_context
            )

        async def emailpassword_sign_up_post(
            form_fields: List[FormField],
            api_options: EPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign up")
            return await original_emailpassword_sign_up_post(
                form_fields, api_options, user_context
            )

        async def thirdparty_sign_in_up_post(
            provider: Provider,
            redirect_uri_info: Union[RedirectUriInfo, None],
            oauth_tokens: Union[Dict[str, Any], None],
            api_options: TPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign in up")
            return await original_thirdparty_sign_in_up_post(
                provider,
                redirect_uri_info,
                oauth_tokens,
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

        original_implementation.emailpassword_email_exists_get = (
            emailpassword_email_exists_get
        )
        original_implementation.generate_password_reset_token_post = (
            generate_password_reset_token_post
        )
        original_implementation.password_reset_post = password_reset_post
        original_implementation.emailpassword_sign_in_post = emailpassword_sign_in_post
        original_implementation.emailpassword_sign_up_post = emailpassword_sign_up_post
        original_implementation.thirdparty_sign_in_up_post = thirdparty_sign_in_up_post
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
                api_options,
                user_context,
            )

        async def create_code_post(
            email: Union[str, None],
            phone_number: Union[str, None],
            api_options: PAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API create code")
            return await original_create_code_post(
                email, phone_number, api_options, user_context
            )

        async def resend_code_post(
            device_id: str,
            pre_auth_session_id: str,
            api_options: PAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API resend code")
            return await original_resend_code_post(
                device_id, pre_auth_session_id, api_options, user_context
            )

        original_implementation.consume_code_post = consume_code_post
        original_implementation.create_code_post = create_code_post
        original_implementation.resend_code_post = resend_code_post
        return original_implementation

    def override_thirdpartypasswordless_apis(
        original_implementation: ThirdpartyPasswordlessAPIInterface,
    ):
        original_consume_code_post = original_implementation.consume_code_post
        original_create_code_post = original_implementation.create_code_post
        original_resend_code_post = original_implementation.resend_code_post
        original_thirdparty_sign_in_up_post = (
            original_implementation.thirdparty_sign_in_up_post
        )
        original_authorisation_url_get = original_implementation.authorisation_url_get

        async def consume_code_post(
            pre_auth_session_id: str,
            user_input_code: Union[str, None],
            device_id: Union[str, None],
            link_code: Union[str, None],
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
                api_options,
                user_context,
            )

        async def create_code_post(
            email: Union[str, None],
            phone_number: Union[str, None],
            api_options: PAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API create code")
            return await original_create_code_post(
                email, phone_number, api_options, user_context
            )

        async def resend_code_post(
            device_id: str,
            pre_auth_session_id: str,
            api_options: PAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API resend code")
            return await original_resend_code_post(
                device_id, pre_auth_session_id, api_options, user_context
            )

        async def thirdparty_sign_in_up_post(
            provider: Provider,
            redirect_uri_info: Union[RedirectUriInfo, None],
            oauth_tokens: Union[Dict[str, Any], None],
            api_options: TPAPIOptions,
            user_context: Dict[str, Any],
        ):
            is_general_error = await check_for_general_error(
                "body", api_options.request
            )
            if is_general_error:
                return GeneralErrorResponse("general error from API sign in up")
            return await original_thirdparty_sign_in_up_post(
                provider,
                redirect_uri_info,
                oauth_tokens,
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

        original_implementation.consume_code_post = consume_code_post
        original_implementation.create_code_post = create_code_post
        original_implementation.resend_code_post = resend_code_post
        original_implementation.thirdparty_sign_in_up_post = thirdparty_sign_in_up_post
        original_implementation.authorisation_url_get = authorisation_url_get
        return original_implementation

    if contact_method is not None and flow_type is not None:
        if contact_method == "PHONE":
            passwordless_init = passwordless.init(
                contact_config=ContactPhoneOnlyConfig(
                    create_and_send_custom_text_message=save_code_text
                ),
                flow_type=flow_type,
                override=passwordless.InputOverrideConfig(
                    apis=override_passwordless_apis
                ),
            )
            thirdpartypasswordless_init = thirdpartypasswordless.init(
                contact_config=ContactPhoneOnlyConfig(
                    create_and_send_custom_text_message=save_code_text
                ),
                flow_type=flow_type,
                providers=providers_list,
                override=thirdpartypasswordless.InputOverrideConfig(
                    apis=override_thirdpartypasswordless_apis
                ),
            )
        elif contact_method == "EMAIL":
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOnlyConfig(
                    create_and_send_custom_email=save_code_email
                ),
                flow_type=flow_type,
                override=passwordless.InputOverrideConfig(
                    apis=override_passwordless_apis
                ),
            )
            thirdpartypasswordless_init = thirdpartypasswordless.init(
                contact_config=ContactEmailOnlyConfig(
                    create_and_send_custom_email=save_code_email
                ),
                flow_type=flow_type,
                providers=providers_list,
                override=thirdpartypasswordless.InputOverrideConfig(
                    apis=override_thirdpartypasswordless_apis
                ),
            )
        else:
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOrPhoneConfig(
                    create_and_send_custom_email=save_code_email,
                    create_and_send_custom_text_message=save_code_text,
                ),
                flow_type=flow_type,
                override=passwordless.InputOverrideConfig(
                    apis=override_passwordless_apis
                ),
            )
            thirdpartypasswordless_init = thirdpartypasswordless.init(
                contact_config=ContactEmailOrPhoneConfig(
                    create_and_send_custom_email=save_code_email,
                    create_and_send_custom_text_message=save_code_text,
                ),
                flow_type=flow_type,
                providers=providers_list,
                override=thirdpartypasswordless.InputOverrideConfig(
                    apis=override_thirdpartypasswordless_apis
                ),
            )
    else:
        passwordless_init = passwordless.init(
            contact_config=ContactPhoneOnlyConfig(
                create_and_send_custom_text_message=save_code_text
            ),
            flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            override=passwordless.InputOverrideConfig(apis=override_passwordless_apis),
        )
        thirdpartypasswordless_init = thirdpartypasswordless.init(
            contact_config=ContactPhoneOnlyConfig(
                create_and_send_custom_text_message=save_code_text
            ),
            flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            providers=providers_list,
            override=thirdpartypasswordless.InputOverrideConfig(
                apis=override_thirdpartypasswordless_apis
            ),
        )

    recipe_list = [
        userroles.init(),
        session.init(override=session.InputOverrideConfig(apis=override_session_apis)),
        emailverification.init(
            mode="OPTIONAL",
            create_and_send_custom_email=ev_create_and_send_custom_email,
            override=EVInputOverrideConfig(apis=override_email_verification_apis),
        ),
        emailpassword.init(
            sign_up_feature=emailpassword.InputSignUpFeature(form_fields),
            reset_password_using_token_feature=emailpassword.InputResetPasswordUsingTokenFeature(
                create_and_send_custom_email=create_and_send_custom_email
            ),
            override=emailpassword.InputOverrideConfig(
                apis=override_email_password_apis,
            ),
        ),
        thirdparty.init(
            sign_in_and_up_feature=thirdparty.SignInAndUpFeature(providers_list),
            override=thirdparty.InputOverrideConfig(apis=override_thirdparty_apis),
        ),
        thirdpartyemailpassword.init(
            sign_up_feature=thirdpartyemailpassword.InputSignUpFeature(form_fields),
            providers=providers_list,
            reset_password_using_token_feature=thirdpartyemailpassword.InputResetPasswordUsingTokenFeature(
                create_and_send_custom_email=create_and_send_custom_email
            ),
            override=thirdpartyemailpassword.InputOverrideConfig(
                apis=override_thirdpartyemailpassword_apis
            ),
        ),
        passwordless_init,
        thirdpartypasswordless_init,
    ]
    init(
        supertokens_config=SupertokensConfig("http://localhost:9000"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="0.0.0.0:" + get_api_port(),
            website_domain=get_website_domain(),
        ),
        framework="django",
        mode=os.environ.get("APP_MODE", "asgi"),  # type: ignore
        recipe_list=recipe_list,
        telemetry=False,
    )
