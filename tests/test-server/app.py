from typing import Any, Callable, Dict, List, Optional, TypeVar, Tuple
from flask import Flask, request, jsonify
from supertokens_python.framework import BaseRequest
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.recipe import accountlinking, multifactorauth
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.totp.recipe import TOTPRecipe
from utils import init_test_claims  # pylint: disable=import-error
from supertokens_python.process_state import ProcessState
from supertokens_python.recipe.dashboard.recipe import DashboardRecipe
from supertokens_python.recipe.emailpassword.recipe import EmailPasswordRecipe
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe
from supertokens_python.recipe.jwt.recipe import JWTRecipe
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.passwordless.recipe import PasswordlessRecipe
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.recipe.thirdparty.recipe import ThirdPartyRecipe
from supertokens_python.recipe.usermetadata.recipe import UserMetadataRecipe
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from test_functions_mapper import (  # pylint: disable=import-error
    get_func,
    get_override_params,
    reset_override_params,
)  # pylint: disable=import-error
from emailpassword import add_emailpassword_routes  # pylint: disable=import-error
from multitenancy import add_multitenancy_routes  # pylint: disable=import-error
from emailverification import (
    add_emailverification_routes,
)  # pylint: disable=import-error
from session import add_session_routes  # pylint: disable=import-error
from supertokens_python import (
    AppInfo,
    Supertokens,
    init,
    InputAppInfo,
    SupertokensConfig,
)
from supertokens_python.recipe import (
    emailpassword,
    session,
    thirdparty,
    emailverification,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.thirdparty.provider import UserFields, UserInfoMap
from supertokens_python.recipe_module import RecipeModule
from supertokens_python.framework.flask.flask_middleware import Middleware
import os
import json
import override_logging

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

    init(
        app_info=InputAppInfo(
            app_name="SuperTokens",
            api_domain="http://api.supertokens.io",
            origin=origin_func,
        ),
        supertokens_config=SupertokensConfig(connection_uri="http://localhost:3567"),
        framework="flask",
        recipe_list=[emailpassword.init(), session.init()],
    )


T = TypeVar("T")


def toCamelCase(snake_case: str) -> str:
    components = snake_case.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def create_override(
    oI: Any, functionName: str, name: str, override_name: Optional[str] = None
):
    implementation = oI if override_name is None else get_func(override_name)(oI)
    originalFunction = getattr(implementation, functionName)

    async def finalFunction(*args: Any, **kwargs: Any):
        override_logging.log_override_event(
            name + "." + toCamelCase(functionName),
            "CALL",
            {"args": args, "kwargs": kwargs},
        )
        try:
            res = await originalFunction(*args, **kwargs)
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
        override_logging.log_override_event(
            name, "CALL", {"args": args, "kwargs": kwargs}
        )
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
                *args: Any, **kwargs: Any  # pylint: disable=unused-argument
            ) -> Any:  # pylint: disable=unused-argument
                return default_value

            impl = default_func

        return logging_override_func_sync(name, impl)(*args, **kwargs)

    return wrapper


def st_reset():
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


def init_st(config: Dict[str, Any]):
    st_reset()
    override_logging.reset_override_logs()

    recipe_list: List[Callable[[AppInfo], RecipeModule]] = []
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
                            config.get("emailDelivery", {}).get("override", None),
                        )
                    ),
                    override=emailpassword.InputOverrideConfig(
                        apis=override_builder_with_logging(
                            "EmailPassword.override.apis",
                            config.get("override", {}).get("apis", None),
                        ),
                        functions=override_builder_with_logging(
                            "EmailPassword.override.functions",
                            config.get("override", {}).get("functions", None),
                        ),
                    ),
                )
            )

        elif recipe_id == "session":
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
                        recipe_config_json.get("on_account_linked"),
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

                        include_in_non_public_tenants_by_default = None

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
                        )
                        providers.append(provider_input)
            recipe_list.append(
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=providers
                    )
                )
            )

        elif recipe_id == "emailverification":
            recipe_config_json = json.loads(recipe_config.get("config", "{}"))
            ev_config: Dict[str, Any] = {"mode": "OPTIONAL"}
            if "mode" in recipe_config_json:
                ev_config["mode"] = recipe_config_json["mode"]

            override_functions = override_builder_with_logging(
                "EmailVerification.override.functions",
                config.get("override", {}).get("functions", None),
            )

            ev_config["override"] = emailverification.InputOverrideConfig(
                functions=override_functions
            )
            recipe_list.append(emailverification.init(**ev_config))
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
    return jsonify([])


@app.route("/test/resetoverrideparams", methods=["POST"])  # type: ignore
def reset_override_params_api():
    override_logging.reset_override_logs()
    reset_override_params()
    return jsonify({"ok": True})


@app.route("/test/getoverridelogs", methods=["GET"])  # type: ignore
def get_override_logs():
    return jsonify({"logs": override_logging.override_logs})


@app.route("/test/mockexternalapi", methods=["POST"])  # type: ignore
def mock_external_api():
    return jsonify({"ok": True})


# @app.route("/create", methods=["POST"])
# def create_session():
#     recipe_user_id = request.json.get("recipeUserId")

#     session = session.create_new_session(request, "public", recipe_user_id)
#     return jsonify({"status": "OK"})


@app.route("/getsession", methods=["POST"])  # type: ignore
@verify_session()
def get_session():
    session: SessionContainer = request.environ["session"]
    return jsonify(
        {"userId": session.get_user_id(), "recipeUserId": session.get_user_id()}
    )


# @app.route("/refreshsession", methods=["POST"])
# def refresh_session():
#     session: SessionContainer = session.refresh_session(request)
#     return jsonify(
#         {"userId": session.get_user_id(), "recipeUserId": session.get_user_id()}
#     )


@app.route("/verify", methods=["GET"])  # type: ignore
@verify_session()
def verify_session_route():
    return jsonify({"status": "OK"})


@app.errorhandler(404)
def not_found(error: Any) -> Any:  # pylint: disable=unused-argument
    return jsonify({"error": f"Route not found: {request.method} {request.path}"}), 404


add_emailpassword_routes(app)
add_multitenancy_routes(app)
add_session_routes(app)
add_emailverification_routes(app)

init_test_claims()

if __name__ == "__main__":
    default_st_init()
    port = int(os.environ.get("API_PORT", api_port))
    app.run(port=port, debug=True)
