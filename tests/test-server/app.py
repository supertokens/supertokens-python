import inspect
import json
import os
import traceback
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, TypeVar, Union

import override_logging
from accountlinking import add_accountlinking_routes  # pylint: disable=import-error
from emailpassword import add_emailpassword_routes  # pylint: disable=import-error
from emailverification import (
    add_emailverification_routes,
)  # pylint: disable=import-error
from flask import Flask, jsonify, request
from multifactorauth import add_multifactorauth_routes
from multitenancy import add_multitenancy_routes  # pylint: disable=import-error
from oauth2provider import add_oauth2provider_routes
from passwordless import add_passwordless_routes  # pylint: disable=import-error
from session import add_session_routes  # pylint: disable=import-error
from supertokens_python import (
    AppInfo,
    InputAppInfo,
    Supertokens,
    SupertokensConfig,
    init,
    process_state,
)
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.framework.flask.flask_middleware import Middleware
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.ingredients.smsdelivery.types import SMSDeliveryConfig
from supertokens_python.post_init_callbacks import PostSTInitCallbacks
from supertokens_python.process_state import ProcessState
from supertokens_python.recipe import (
    accountlinking,
    dashboard,
    emailpassword,
    emailverification,
    multifactorauth,
    oauth2provider,
    passwordless,
    session,
    thirdparty,
    totp,
    webauthn,
)
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.dashboard.recipe import DashboardRecipe
from supertokens_python.recipe.emailpassword.recipe import EmailPasswordRecipe
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe
from supertokens_python.recipe.jwt.recipe import JWTRecipe
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.passwordless.recipe import PasswordlessRecipe
from supertokens_python.recipe.session import InputErrorHandlers, SessionContainer
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.recipe.session.utils import TokenTransferMethod
from supertokens_python.recipe.thirdparty.provider import UserFields, UserInfoMap
from supertokens_python.recipe.thirdparty.recipe import ThirdPartyRecipe
from supertokens_python.recipe.totp.recipe import TOTPRecipe
from supertokens_python.recipe.usermetadata.recipe import UserMetadataRecipe
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnEmailDeliveryInput,
)
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.recipe.webauthn.types.config import WebauthnConfig
from supertokens_python.recipe_module import RecipeModule
from supertokens_python.types import RecipeUserId
from test_functions_mapper import (  # pylint: disable=import-error
    get_func,
    get_override_params,
    reset_override_params,
)  # pylint: disable=import-error
from thirdparty import add_thirdparty_routes  # pylint: disable=import-error
from totp import add_totp_routes  # pylint: disable=import-error
from usermetadata import add_usermetadata_routes
from webauthn import add_webauthn_routes

from supertokens import add_supertokens_routes  # pylint: disable=import-error

app = Flask(__name__)
Middleware(app)

# Global variables
api_port = 3030


def default_st_init():
    def origin_func(  # pylint: disable=unused-argument, dangerous-default-value
        request: Optional[BaseRequest] = None,
        context: Dict[  # pylint: disable=unused-argument, dangerous-default-value
            str, Any
        ] = {},  # pylint: disable=unused-argument, dangerous-default-value
    ) -> str:
        if request is None:
            return "http://localhost:8080"
        origin = request.get_header("origin")
        if origin is not None:
            return origin
        return "http://localhost:8080"

    core_host: str = os.environ.get("SUPERTOKENS_CORE_HOST", "localhost")
    core_port: str = os.environ.get("SUPERTOKENS_CORE_PORT", "3567")
    core_url = f"http://{core_host}:{core_port}"

    init(
        app_info=InputAppInfo(
            app_name="SuperTokens",
            api_domain="http://api.supertokens.io",
            origin=origin_func,
        ),
        supertokens_config=SupertokensConfig(connection_uri=core_url),
        framework="flask",
        recipe_list=[emailpassword.init(), session.init()],
    )


T = TypeVar("T")


def toCamelCase(snake_case: str) -> str:
    components = snake_case.split("_")
    res = components[0] + "".join(x.title() for x in components[1:])
    # Convert 'post', 'get', or 'put' at the end to uppercase
    if res.endswith("Post"):
        res = res[:-4] + "POST"
    if res.endswith("Get"):
        res = res[:-3] + "GET"
    if res.endswith("Put"):
        res = res[:-3] + "PUT"
    return res


def create_override(
    oI: Any, functionName: str, name: str, override_name: Optional[str] = None
):
    implementation = oI if override_name is None else get_func(override_name)(oI)
    originalFunction = getattr(implementation, functionName)

    async def finalFunction(*args: Any, **kwargs: Any):
        if len(args) > 0:
            override_logging.log_override_event(
                name + "." + toCamelCase(functionName),
                "CALL",
                args,
            )
        else:
            override_logging.log_override_event(
                name + "." + toCamelCase(functionName), "CALL", kwargs
            )
        try:
            if inspect.iscoroutinefunction(originalFunction):
                res = await originalFunction(*args, **kwargs)
            else:
                res = originalFunction(*args, **kwargs)
            override_logging.log_override_event(
                name + "." + toCamelCase(functionName), "RES", res
            )
            return res
        except Exception as e:
            override_logging.log_override_event(
                name + "." + toCamelCase(functionName), "REJ", e
            )
            raise e

    setattr(oI, functionName, finalFunction)


def override_builder_with_logging(
    name: str, override_name: Optional[str] = None
) -> Callable[[T], T]:
    def builder(oI: T) -> T:
        members = [
            attr
            for attr in dir(oI)
            if callable(getattr(oI, attr)) and not attr.startswith("__")
        ]
        for member in members:
            create_override(oI, member, name, override_name)
        return oI

    return builder


def logging_override_func_sync(name: str, c: Any) -> Any:
    def inner(*args: Any, **kwargs: Any) -> Any:
        if len(args) > 0:
            override_logging.log_override_event(name, "CALL", args)
        else:
            override_logging.log_override_event(name, "CALL", kwargs)
        try:
            res = c(*args, **kwargs)
            override_logging.log_override_event(name, "RES", res)
            return res
        except Exception as e:
            override_logging.log_override_event(name, "REJ", e)
            raise e

    return inner


def callback_with_log(
    name: str, override_name: Optional[str], default_value: Any = None
) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if override_name:
            impl = get_func(override_name)
        else:

            async def default_func(  # pylint: disable=unused-argument
                *args: Any,
                **kwargs: Any,  # pylint: disable=unused-argument
            ) -> Any:  # pylint: disable=unused-argument
                return default_value

            impl = default_func

        return logging_override_func_sync(name, impl)(*args, **kwargs)

    return wrapper


def st_reset():
    PostSTInitCallbacks.reset()
    override_logging.reset_override_logs()
    reset_override_params()
    ProcessState.get_instance().reset()
    Supertokens.reset()
    SessionRecipe.reset()
    EmailPasswordRecipe.reset()
    EmailVerificationRecipe.reset()
    ThirdPartyRecipe.reset()
    PasswordlessRecipe.reset()
    JWTRecipe.reset()
    UserMetadataRecipe.reset()
    UserRolesRecipe.reset()
    DashboardRecipe.reset()
    PasswordlessRecipe.reset()
    MultitenancyRecipe.reset()
    AccountLinkingRecipe.reset()
    TOTPRecipe.reset()
    MultiFactorAuthRecipe.reset()
    OAuth2ProviderRecipe.reset()
    OpenIdRecipe.reset()
    WebauthnRecipe.reset()


def init_st(config: Dict[str, Any]):
    st_reset()
    override_logging.reset_override_logs()

    recipe_list: List[Callable[[AppInfo], RecipeModule]] = [
        dashboard.init(api_key="test")
    ]
    for recipe_config in config.get("recipeList", []):
        recipe_id = recipe_config.get("recipeId")
        if recipe_id == "emailpassword":
            sign_up_feature_input = None
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            if "signUpFeature" in recipe_config_json:
                sign_up_feature = recipe_config_json["signUpFeature"]
                if "formFields" in sign_up_feature:
                    form_fields: List[emailpassword.InputFormField] = []
                    for field in sign_up_feature["formFields"]:
                        form_fields.append(emailpassword.InputFormField(id=field["id"]))
                    sign_up_feature_input = emailpassword.InputSignUpFeature(
                        form_fields=form_fields
                    )

            recipe_list.append(
                emailpassword.init(
                    sign_up_feature=sign_up_feature_input,
                    email_delivery=EmailDeliveryConfig(
                        override=override_builder_with_logging(
                            "EmailPassword.emailDelivery.override",
                            recipe_config_json.get("emailDelivery", {}).get(
                                "override", None
                            ),
                        )
                    ),
                    override=emailpassword.InputOverrideConfig(
                        apis=override_builder_with_logging(
                            "EmailPassword.override.apis",
                            recipe_config_json.get("override", {}).get("apis", None),
                        ),
                        functions=override_builder_with_logging(
                            "EmailPassword.override.functions",
                            recipe_config_json.get("override", {}).get(
                                "functions", None
                            ),
                        ),
                    ),
                )
            )
        elif recipe_id == "session":

            async def custom_unauthorised_callback(
                _: BaseRequest, __: str, response: BaseResponse
            ) -> BaseResponse:
                response.set_status_code(401)
                response.set_json_content(
                    content={"type": "UNAUTHORISED", "message": "unauthorised"}
                )
                return response

            def get_token_transfer_method(
                _: BaseRequest,
                __: bool,
                ___: Dict[str, Any],
            ) -> Union[TokenTransferMethod, Literal["any"]]:
                return recipe_config_json.get("getTokenTransferMethod", "any")

            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            recipe_list.append(
                session.init(
                    cookie_secure=recipe_config_json.get("cookieSecure"),
                    cookie_same_site=recipe_config_json.get("cookieSameSite"),
                    session_expired_status_code=recipe_config_json.get(
                        "sessionExpiredStatusCode"
                    ),
                    invalid_claim_status_code=recipe_config_json.get(
                        "invalidClaimStatusCode"
                    ),
                    cookie_domain=recipe_config_json.get("cookieDomain"),
                    older_cookie_domain=recipe_config_json.get("olderCookieDomain"),
                    anti_csrf=recipe_config_json.get("antiCsrf"),
                    expose_access_token_to_frontend_in_cookie_based_auth=recipe_config_json.get(
                        "exposeAccessTokenToFrontendInCookieBasedAuth"
                    ),
                    use_dynamic_access_token_signing_key=recipe_config_json.get(
                        "useDynamicAccessTokenSigningKey"
                    ),
                    get_token_transfer_method=get_token_transfer_method,
                    override=session.InputOverrideConfig(
                        apis=override_builder_with_logging(
                            "Session.override.apis",
                            recipe_config_json.get("override", {}).get("apis", None),
                        ),
                        functions=override_builder_with_logging(
                            "Session.override.functions",
                            recipe_config_json.get("override", {}).get(
                                "functions", None
                            ),
                        ),
                    ),
                    error_handlers=InputErrorHandlers(
                        on_unauthorised=custom_unauthorised_callback
                    ),
                )
            )
        elif recipe_id == "accountlinking":
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            recipe_list.append(
                accountlinking.init(
                    should_do_automatic_account_linking=callback_with_log(
                        "AccountLinking.shouldDoAutomaticAccountLinking",
                        recipe_config_json.get("shouldDoAutomaticAccountLinking"),
                        accountlinking.ShouldNotAutomaticallyLink(),
                    ),
                    on_account_linked=callback_with_log(
                        "AccountLinking.onAccountLinked",
                        recipe_config_json.get("onAccountLinked"),
                    ),
                    override=accountlinking.InputOverrideConfig(
                        functions=override_builder_with_logging(
                            "AccountLinking.override.functions",
                            recipe_config_json.get("override", {}).get(
                                "functions", None
                            ),
                        ),
                    ),
                )
            )
        elif recipe_id == "thirdparty":
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            providers: List[thirdparty.ProviderInput] = []
            if "signInAndUpFeature" in recipe_config_json:
                sign_in_up_feature = recipe_config_json["signInAndUpFeature"]
                if "providers" in sign_in_up_feature:
                    for provider in sign_in_up_feature["providers"]:
                        user_info_map: Optional[UserInfoMap] = None

                        if "userInfoMap" in provider["config"]:
                            map_from_payload = provider["config"]["userInfoMap"].get(
                                "fromIdTokenPayload", {}
                            )
                            map_from_api = provider["config"]["userInfoMap"].get(
                                "fromUserInfoAPI", {}
                            )
                            user_info_map = UserInfoMap(
                                from_id_token_payload=UserFields(
                                    user_id=map_from_payload.get("userId"),
                                    email=map_from_payload.get("email"),
                                    email_verified=map_from_payload.get(
                                        "emailVerified"
                                    ),
                                ),
                                from_user_info_api=UserFields(
                                    user_id=map_from_api.get("userId"),
                                    email=map_from_api.get("email"),
                                    email_verified=map_from_api.get("emailVerified"),
                                ),
                            )

                        include_in_non_public_tenants_by_default = False

                        if "includeInNonPublicTenantsByDefault" in provider:
                            include_in_non_public_tenants_by_default = provider[
                                "includeInNonPublicTenantsByDefault"
                            ]

                        provider_input = thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id=provider["config"]["thirdPartyId"],
                                name=provider["config"].get("name"),
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id=c["clientId"],
                                        client_secret=c.get("clientSecret"),
                                        client_type=c.get("clientType"),
                                        scope=c.get("scope"),
                                        force_pkce=c.get("forcePKCE", False),
                                        additional_config=c.get("additionalConfig"),
                                    )
                                    for c in provider["config"].get("clients", [])
                                ],
                                authorization_endpoint=provider["config"].get(
                                    "authorizationEndpoint"
                                ),
                                authorization_endpoint_query_params=provider[
                                    "config"
                                ].get("authorizationEndpointQueryParams"),
                                token_endpoint=provider["config"].get("tokenEndpoint"),
                                token_endpoint_body_params=provider["config"].get(
                                    "tokenEndpointBodyParams"
                                ),
                                user_info_endpoint=provider["config"].get(
                                    "userInfoEndpoint"
                                ),
                                user_info_endpoint_query_params=provider["config"].get(
                                    "userInfoEndpointQueryParams"
                                ),
                                user_info_endpoint_headers=provider["config"].get(
                                    "userInfoEndpointHeaders"
                                ),
                                jwks_uri=provider["config"].get("jwksURI"),
                                oidc_discovery_endpoint=provider["config"].get(
                                    "oidcDiscoveryEndpoint"
                                ),
                                user_info_map=user_info_map,
                                require_email=provider["config"].get(
                                    "requireEmail", True
                                ),
                            ),
                            include_in_non_public_tenants_by_default=include_in_non_public_tenants_by_default,
                            override=override_builder_with_logging(
                                "ThirdParty.providers.override",
                                provider.get("override", None),
                            ),
                        )
                        providers.append(provider_input)
            recipe_list.append(
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=providers
                    ),
                    override=thirdparty.InputOverrideConfig(
                        functions=override_builder_with_logging(
                            "ThirdParty.override.functions",
                            recipe_config_json.get("override", {}).get(
                                "functions", None
                            ),
                        ),
                        apis=override_builder_with_logging(
                            "ThirdParty.override.apis",
                            recipe_config_json.get("override", {}).get("apis", None),
                        ),
                    ),
                )
            )
        elif recipe_id == "emailverification":
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))

            from supertokens_python.recipe.emailverification.interfaces import (
                UnknownUserIdError,
            )
            from supertokens_python.recipe.emailverification.utils import (
                OverrideConfig as EmailVerificationOverrideConfig,
            )

            recipe_list.append(
                emailverification.init(
                    mode=(
                        recipe_config_json["mode"]
                        if "mode" in recipe_config_json
                        else "OPTIONAL"
                    ),
                    override=EmailVerificationOverrideConfig(
                        apis=override_builder_with_logging(
                            "EmailVerification.override.apis",
                            recipe_config_json.get("override", {}).get("apis", None),
                        ),
                        functions=override_builder_with_logging(
                            "EmailVerification.override.functions",
                            recipe_config_json.get("override", {}).get(
                                "functions", None
                            ),
                        ),
                    ),
                    get_email_for_recipe_user_id=callback_with_log(
                        "EmailVerification.getEmailForRecipeUserId",
                        recipe_config_json.get("getEmailForRecipeUserId"),
                        UnknownUserIdError(),
                    ),
                    email_delivery=EmailDeliveryConfig(
                        override=override_builder_with_logging(
                            "EmailVerification.emailDelivery.override",
                            recipe_config_json.get("emailDelivery", {}).get(
                                "override", None
                            ),
                        )
                    ),
                )
            )
        elif recipe_id == "multifactorauth":
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            recipe_list.append(
                multifactorauth.init(
                    first_factors=recipe_config_json.get("firstFactors", None),
                    override=multifactorauth.OverrideConfig(
                        functions=override_builder_with_logging(
                            "MultifactorAuth.override.functions",
                            recipe_config_json.get("override", {}).get(
                                "functions", None
                            ),
                        ),
                        apis=override_builder_with_logging(
                            "MultifactorAuth.override.apis",
                            recipe_config_json.get("override", {}).get("apis", None),
                        ),
                    ),
                )
            )
        elif recipe_id == "passwordless":
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            contact_config: passwordless.ContactConfig = (
                passwordless.ContactEmailOnlyConfig()
            )
            if recipe_config_json.get("contactMethod") == "PHONE":
                contact_config = passwordless.ContactPhoneOnlyConfig()
            elif recipe_config_json.get("contactMethod") == "EMAIL_OR_PHONE":
                contact_config = passwordless.ContactEmailOrPhoneConfig()

            class EmailDeliveryCustom(passwordless.EmailDeliveryInterface[Any]):
                async def send_email(
                    self, template_vars: Any, user_context: Dict[str, Any]
                ) -> None:
                    f = get_func("passwordless.init.emailDelivery.service.sendEmail")
                    return f(template_vars, user_context)

            class SMSDeliveryCustom(passwordless.SMSDeliveryInterface[Any]):
                async def send_sms(
                    self, template_vars: Any, user_context: Dict[str, Any]
                ) -> None:
                    f = get_func("passwordless.init.smsDelivery.service.sendSms")
                    return f(template_vars, user_context)

            recipe_list.append(
                passwordless.init(
                    email_delivery=EmailDeliveryConfig(
                        service=EmailDeliveryCustom(),
                        override=override_builder_with_logging(
                            "Passwordless.emailDelivery.override",
                            config.get("emailDelivery", {}).get("override", None),
                        ),
                    ),
                    sms_delivery=SMSDeliveryConfig(
                        service=SMSDeliveryCustom(),
                        override=override_builder_with_logging(
                            "Passwordless.smsDelivery.override",
                            config.get("smsDelivery", {}).get("override", None),
                        ),
                    ),
                    contact_config=contact_config,
                    flow_type=recipe_config_json.get("flowType"),
                    override=passwordless.InputOverrideConfig(
                        apis=override_builder_with_logging(
                            "Passwordless.override.apis",
                            recipe_config_json.get("override", {}).get("apis"),
                        ),
                        functions=override_builder_with_logging(
                            "Passwordless.override.functions",
                            recipe_config_json.get("override", {}).get("functions"),
                        ),
                    ),
                )
            )
        elif recipe_id == "totp":
            from supertokens_python.recipe.totp.types import (
                OverrideConfig as TOTPOverrideConfig,
            )

            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            recipe_list.append(
                totp.init(
                    config=totp.TOTPConfig(
                        default_period=recipe_config_json.get("defaultPeriod"),
                        default_skew=recipe_config_json.get("defaultSkew"),
                        issuer=recipe_config_json.get("issuer"),
                        override=TOTPOverrideConfig(
                            apis=override_builder_with_logging(
                                "Multitenancy.override.apis",
                                recipe_config_json.get("override", {}).get("apis"),
                            ),
                            functions=override_builder_with_logging(
                                "Multitenancy.override.functions",
                                recipe_config_json.get("override", {}).get("functions"),
                            ),
                        ),
                    )
                )
            )
        elif recipe_id == "oauth2provider":
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            recipe_list.append(
                oauth2provider.init(
                    override=oauth2provider.InputOverrideConfig(
                        apis=override_builder_with_logging(
                            "OAuth2Provider.override.apis",
                            recipe_config_json.get("override", {}).get("apis"),
                        ),
                        functions=override_builder_with_logging(
                            "OAuth2Provider.override.functions",
                            recipe_config_json.get("override", {}).get("functions"),
                        ),
                    )
                )
            )
        elif recipe_id == "webauthn":
            from supertokens_python.recipe.webauthn.types.config import (
                OverrideConfig as WebauthnOverrideConfig,
            )

            class WebauthnEmailDeliveryConfig(
                EmailDeliveryConfig[TypeWebauthnEmailDeliveryInput]
            ):
                pass

            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            recipe_list.append(
                webauthn.init(
                    WebauthnConfig(
                        get_relying_party_id=callback_with_log(
                            "WebAuthn.getRelyingPartyId",
                            recipe_config_json.get("getRelyingPartyId"),
                        )
                        if "getRelyingPartyId" in recipe_config_json
                        else None,
                        get_relying_party_name=callback_with_log(
                            "WebAuthn.getRelyingPartyName",
                            recipe_config_json.get("getRelyingPartyName"),
                        )
                        if "getRelyingPartyName" in recipe_config_json
                        else None,
                        validate_email_address=callback_with_log(
                            "WebAuthn.validateEmailAddress",
                            recipe_config_json.get("validateEmailAddress"),
                        )
                        if "validateEmailAddress" in recipe_config_json
                        else None,
                        get_origin=callback_with_log(
                            "WebAuthn.getOrigin",
                            recipe_config_json.get("getOrigin"),
                        )
                        if "getOrigin" in recipe_config_json
                        else None,
                        email_delivery=WebauthnEmailDeliveryConfig(
                            override=override_builder_with_logging(
                                "WebAuthn.emailDelivery.override",
                                recipe_config_json.get("emailDelivery", {}).get(
                                    "override"
                                ),
                            ),
                        ),
                        override=WebauthnOverrideConfig(
                            apis=override_builder_with_logging(
                                "WebAuthn.override.apis",
                                recipe_config_json.get("override", {}).get("apis"),
                            ),  # type: ignore
                            functions=override_builder_with_logging(
                                "WebAuthn.override.functions",
                                recipe_config_json.get("override", {}).get("functions"),
                            ),  # type: ignore
                        ),
                    ),
                )
            )

    interceptor_func = None
    if config.get("supertokens", {}).get("networkInterceptor") is not None:
        interceptor_func = get_func(
            config.get("supertokens", {}).get("networkInterceptor")
        )

    def network_interceptor_func(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[
        str, str, Dict[str, Any], Optional[Dict[str, Any]], Optional[Dict[str, Any]]
    ]:
        def inner(
            url: str,
            method: str,
            headers: Dict[str, Any],
            params: Optional[Dict[str, Any]],
            body: Optional[Dict[str, Any]],
            user_context: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
            # print(
            #     "-------------------------------------------!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            # )
            # print(url)
            # import traceback
            # print("Stack trace:")
            # traceback.print_stack()

            if interceptor_func is not None:
                resp = interceptor_func(
                    url, method, headers, params, body, user_context
                )
                return {
                    "url": resp[0],
                    "method": resp[1],
                    "headers": resp[2],
                    "params": resp[3],
                    "body": resp[4],
                    "user_context": resp[5],
                }
            return {
                "url": url,
                "method": method,
                "headers": headers,
                "params": params,
                "body": body,
                "user_context": user_context,
            }

        res = logging_override_func_sync("networkInterceptor", inner)(
            url, method, headers, params, body, user_context
        )
        return (
            res.get("url"),
            res.get("method"),
            res.get("headers"),
            res.get("params"),
            res.get("body"),
        )

    try:
        init(
            app_info=InputAppInfo(
                app_name=config["appInfo"]["appName"],
                api_domain=config["appInfo"]["apiDomain"],
                website_domain=config["appInfo"]["websiteDomain"],
            ),
            supertokens_config=SupertokensConfig(
                connection_uri=config["supertokens"]["connectionURI"],
                network_interceptor=network_interceptor_func,
            ),
            framework="flask",
            recipe_list=recipe_list,
        )
    except Exception as e:
        st_reset()
        default_st_init()
        raise e


# Routes
@app.route("/test/ping", methods=["GET"])  # type: ignore
def ping():
    return jsonify({"ok": True})


@app.route("/test/init", methods=["POST"])  # type: ignore
def init_handler():
    if request.json is None:
        return jsonify({"error": "No config provided"}), 400
    config = request.json.get("config")
    if config:
        init_st(json.loads(config))
        return jsonify({"ok": True})
    return jsonify({"error": "No config provided"}), 400


@app.route("/test/overrideparams", methods=["GET"])  # type: ignore
def override_params():
    return jsonify(get_override_params().to_json())


@app.route("/test/featureflag", methods=["GET"])  # type: ignore
def feature_flag():
    return jsonify(["removedOverwriteSessionDuringSignInUp"])


@app.route("/test/resetoverrideparams", methods=["POST"])  # type: ignore
def reset_override_params_api():
    override_logging.reset_override_logs()
    reset_override_params()
    return jsonify({"ok": True})


@app.route("/test/resetoverridelogs", methods=["GET"])  # type: ignore
def reset_override_logs():
    override_logging.reset_override_logs()
    return jsonify({"ok": True})


@app.route("/test/getoverridelogs", methods=["GET"])  # type: ignore
def get_override_logs():
    return jsonify({"logs": override_logging.override_logs})


@app.route("/test/mockexternalapi", methods=["POST"])  # type: ignore
def mock_external_api():
    return jsonify({"ok": True})


@app.route("/create", methods=["POST"])  # type: ignore
def create_session_api():  # type: ignore
    data = request.json
    if data is None:
        return jsonify({"status": "MISSING_DATA_ERROR"})
    recipe_user_id = RecipeUserId(data.get("recipeUserId"))

    from supertokens_python.recipe.session.syncio import create_new_session

    create_new_session(request, "public", recipe_user_id)
    return jsonify({"status": "OK"})


@app.route("/getsession", methods=["POST"])  # type: ignore
@verify_session()
def get_session():
    from supertokens_python.recipe.session.syncio import get_session

    session = get_session(request)
    assert session is not None
    return jsonify(
        {
            "userId": session.get_user_id(),
            "recipeUserId": session.get_recipe_user_id().get_as_string(),
        }
    )


@app.route("/refreshsession", methods=["POST"])  # type: ignore
def refresh_session_api():  # type: ignore
    from supertokens_python.recipe.session.syncio import refresh_session

    session: SessionContainer = refresh_session(request)
    return jsonify(
        {
            "userId": session.get_user_id(),
            "recipeUserId": session.get_recipe_user_id().get_as_string(),
        }
    )


@app.route("/verify", methods=["GET"])  # type: ignore
@verify_session()
def verify_session_route():
    return jsonify({"status": "OK"})


@app.route("/test/waitforevent", methods=["GET"])  # type: ignore
def wait_for_event_api():  # type: ignore
    event = request.args.get("event")
    if not event:
        raise ValueError("event query param missing")

    event_enum = process_state.PROCESS_STATE(int(event))
    instance = process_state.ProcessState.get_instance()
    event_result = instance.wait_for_event(event_enum)
    if event_result is None:
        return jsonify(None)
    else:
        return jsonify("Found")


@app.errorhandler(404)
def not_found(error: Any) -> Any:  # pylint: disable=unused-argument
    return jsonify({"error": f"Route not found: {request.method} {request.path}"}), 404


@app.errorhandler(Exception)  # type: ignore
def handle_exception(e: Exception):
    # Print the error and stack trace
    print(f"An error occurred: {str(e)}")
    traceback.print_exc()

    # Return JSON response with 500 status code
    return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


add_emailpassword_routes(app)
add_multitenancy_routes(app)
add_session_routes(app)
add_emailverification_routes(app)
add_thirdparty_routes(app)
add_accountlinking_routes(app)
add_passwordless_routes(app)
add_totp_routes(app)
add_supertokens_routes(app)
add_usermetadata_routes(app)
add_multifactorauth_routes(app)
add_oauth2provider_routes(app)
add_webauthn_routes(app)

if __name__ == "__main__":
    default_st_init()
    port = int(os.environ.get("API_PORT", api_port))
    app.run(port=port, debug=True)
