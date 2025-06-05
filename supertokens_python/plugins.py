from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    TypeVar,
    Union,
    runtime_checkable,
)

from typing_extensions import Protocol

from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse

# from supertokens_python.recipe.accountlinking.types import AccountLinkingConfig
# from supertokens_python.recipe.dashboard.utils import DashboardConfig
# from supertokens_python.recipe.emailpassword.utils import EmailPasswordConfig
# from supertokens_python.recipe.emailverification.utils import EmailVerificationConfig
# from supertokens_python.recipe.jwt.utils import JWTConfig
# from supertokens_python.recipe.multifactorauth.types import MultiFactorAuthConfig
# from supertokens_python.recipe.multitenancy.utils import MultitenancyConfig
# from supertokens_python.recipe.oauth2provider.utils import OAuth2ProviderConfig
# from supertokens_python.recipe.openid.utils import OpenIdConfig
# from supertokens_python.recipe.passwordless.utils import PasswordlessConfig
if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import (
        SessionClaimValidator,
        SessionContainer,
    )
    from supertokens_python.supertokens import SupertokensPublicConfig

# from supertokens_python.recipe.session.utils import SessionConfig
# from supertokens_python.recipe.thirdparty.utils import ThirdPartyConfig
# from supertokens_python.recipe.totp.types import TOTPConfig
# from supertokens_python.recipe.usermetadata.utils import UserMetadataConfig
# from supertokens_python.recipe.userroles.utils import UserRolesConfig
from supertokens_python.types import MaybeAwaitable
from supertokens_python.types.base import UserContext
from supertokens_python.types.response import CamelCaseBaseModel

T = TypeVar("T")
# T = TypeVar("T", bound=Union[AccountLinkingConfig, DashboardConfig, EmailPasswordConfig,
#     EmailVerificationConfig, JWTConfig, MultiFactorAuthConfig, MultitenancyConfig,
#     OAuth2ProviderConfig, OpenIdConfig, PasswordlessConfig, SessionConfig,
#     ThirdPartyConfig, TOTPConfig, UserMetadataConfig, UserRolesConfig])


# class AllRecipeConfigs:
#     # These generally have no Input config type
#     accountlinking: AccountLinkingConfig
#     dashboard: DashboardConfig
#     emailpassword: EmailPasswordConfig
#     emailverification: EmailVerificationConfig
#     jwt: JWTConfig
#     multifactorauth: MultiFactorAuthConfig
#     multitenancy: MultitenancyConfig
#     oauth2provider: OAuth2ProviderConfig
#     openid: OpenIdConfig
#     passwordless: PasswordlessConfig
#     session: SessionConfig
#     thirdparty: ThirdPartyConfig
#     totp: TOTPConfig  # This is the input config type
#     usermetadata: UserMetadataConfig
#     userroles: UserRolesConfig
#     # webauthn: WebauthnConfig


class RecipePluginOverride:
    # TODO: Define a base class for the Config/RecipeInterface/ApiInterface classes, and use it here
    functions: Optional[Callable[[Any], Any]]
    apis: Optional[Callable[[Any], Any]]
    config: Optional[Callable[[Any], Any]]


# export type AllRecipeConfigs = {
#     accountlinking: AccountLinkingTypeInput & { override?: { apis: never } };
#     dashboard: DashboardTypeInput;
#     emailpassword: EmailPasswordTypeInput;
#     emailverification: EmailVerificationTypeInput;
#     jwt: JWTTypeInput;
#     multifactorauth: MultifactorAuthTypeInput;
#     multitenancy: MultitenancyTypeInput;
#     oauth2provider: OAuth2ProviderTypeInput;
#     openid: OpenIdTypeInput;
#     passwordless: PasswordlessTypeInput;
#     session: SessionTypeInput;
#     thirdparty: ThirdPartyTypeInput;
#     totp: TotpTypeInput;
#     usermetadata: UserMetadataTypeInput;
#     userroles: UserRolesTypeInput;
# };

# export type RecipePluginOverride<T extends keyof AllRecipeConfigs> = {
#     functions?: NonNullable<AllRecipeConfigs[T]["override"]>["functions"];
#     apis?: NonNullable<AllRecipeConfigs[T]["override"]>["apis"];
#     config?: (config: AllRecipeConfigs[T]) => AllRecipeConfigs[T];
# };


class PluginRouteHandlerResponse(CamelCaseBaseModel):
    status: int
    body: Any


@runtime_checkable
class PluginRouteHandlerHandlerFunction(Protocol):
    def __call__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        session: Optional["SessionContainer"],
        user_context: UserContext,
    ) -> BaseResponse: ...


@runtime_checkable
class OverrideGlobalClaimValidatorsFunction(Protocol):
    def __call__(
        self,
        global_claim_validators: List["SessionClaimValidator"],
        session: "SessionContainer",
        user_context: UserContext,
    ) -> MaybeAwaitable[List["SessionClaimValidator"]]: ...


class VerifySessionOptions(CamelCaseBaseModel):
    session_required: Optional[bool] = None
    anti_csrf_check: Optional[bool] = None
    check_database: Optional[bool] = None
    override_global_claim_validators: Optional[
        OverrideGlobalClaimValidatorsFunction
    ] = None


class PluginRouteHandler:
    method: str
    path: str
    verify_session_options: Optional[VerifySessionOptions]
    handler: PluginRouteHandlerHandlerFunction


@runtime_checkable
class SuperTokensPluginInit(Protocol):
    def __call__(
        self,
        config: "SupertokensPublicConfig",
        all_plugins: List["SuperTokensPublicPlugin"],
        sdk_version: str,
    ) -> None: ...


class PluginDependenciesOkResponse(CamelCaseBaseModel):
    status: Literal["OK"] = "OK"
    plugins_to_add: List["SuperTokensPlugin"]


class PluginDependenciesErrorResponse(CamelCaseBaseModel):
    status: Literal["ERROR"] = "ERROR"
    message: str


@runtime_checkable
class SuperTokensPluginDependencies(Protocol):
    def __call__(
        self,
        config: "SupertokensPublicConfig",
        plugins_above: List["SuperTokensPublicPlugin"],
        sdk_version: str,
    ) -> Union[PluginDependenciesOkResponse, PluginDependenciesErrorResponse]: ...


class PluginRouteHandlerFunctionOkResponse(CamelCaseBaseModel):
    status: Literal["OK"] = "OK"
    plugins_to_add: List["SuperTokensPlugin"]


class PluginRouteHandlerFunctionErrorResponse(CamelCaseBaseModel):
    status: Literal["ERROR"] = "ERROR"
    message: str


@runtime_checkable
class PluginRouteHandlerFunction(Protocol):
    def __call__(
        self,
        config: "SupertokensPublicConfig",
        all_plugins: List["SuperTokensPublicPlugin"],
        sdk_version: str,
    ) -> Union[
        PluginRouteHandlerFunctionOkResponse, PluginRouteHandlerFunctionErrorResponse
    ]: ...


@runtime_checkable
class PluginConfig(Protocol):
    def __call__(
        self, config: "SupertokensPublicConfig"
    ) -> "SupertokensPublicConfig": ...


class SuperTokensPluginBase(CamelCaseBaseModel):
    id: str
    version: Optional[str] = None
    compatible_sdk_versions: Union[str, List[str]]
    exports: Optional[Dict[str, Any]] = None


OverrideMap = Dict[str, Any]


class SuperTokensPlugin(SuperTokensPluginBase):
    init: Optional[SuperTokensPluginInit] = None
    dependencies: Optional[SuperTokensPluginDependencies] = None
    # TODO: Add types for recipes
    # overrideMap?: {
    #     [recipeId in keyof AllRecipeConfigs]?: RecipePluginOverride<recipeId> & {
    #         recipeInitRequired?: boolean | ((sdkVersion: string) => boolean);
    #     };
    # };
    override_map: Optional[OverrideMap] = None
    route_handlers: Optional[
        Union[List[PluginRouteHandler], PluginRouteHandlerFunction]
    ] = None
    config: Optional[PluginConfig] = None


class SuperTokensPublicPlugin(SuperTokensPluginBase):
    initialized: bool

    @classmethod
    def from_plugin(cls, plugin: SuperTokensPlugin) -> "SuperTokensPublicPlugin":
        return cls(
            id=plugin.id,
            initialized=plugin.init is None,
            version=plugin.version,
            exports=plugin.exports,
            compatible_sdk_versions=plugin.compatible_sdk_versions,
        )


class ConfigOverrideBase:
    functions: Optional[Callable[[Any], Any]] = None
    apis: Optional[Callable[[Any], Any]] = None


def apply_plugins(recipe_id: str, config: T, plugins: List[OverrideMap]) -> T:
    # print("Startnig apply_plugins")

    def default_fn_override(original_implementation: T) -> T:
        return original_implementation

    def default_api_override(original_implementation: T) -> T:
        return original_implementation

    if config.override is None:
        config.override = ConfigOverrideBase()
        config.override.functions = default_fn_override
        config.override.apis = default_api_override

    function_overrides = getattr(config.override, "functions", default_fn_override)
    api_overrides = getattr(config.override, "apis", default_api_override)

    # print("config overrides", function_overrides, api_overrides)

    function_layers: list[Any] = []
    api_layers: list[Any] = []
    if function_overrides is not None:
        function_layers.append(function_overrides)
    if api_overrides is not None:
        api_layers.append(api_overrides)

    # print("Starting plugin iteration")
    for plugin in plugins:
        # print(f"{plugin=}")
        overrides = plugin[recipe_id]
        # print(f"{overrides=}")
        if overrides is not None:
            if overrides.config is not None:
                config = overrides.config(config)

            if overrides.functions is not None:
                function_layers.append(overrides.functions)
            if overrides.apis is not None:
                api_layers.append(overrides.apis)

    # function_layers.reverse()
    # api_layers.reverse()

    # Apply the user override first, followed by the plugin overrides
    # Example: [user_override, plugin_dep_1, plugin_1]
    # final_override(oI) -> plugin_1_oI
    # plugin_1(plugin_dep_1_oI) -> plugin_1_oI
    # plugin_dep_1(user_override_oI) -> plugin_dep_1_oI
    # user_override(oI) -> user_override_oI

    if len(function_layers) > 0:

        def fn_override(original_implementation: Any) -> Any:
            for function_layer in reversed(function_layers):
                # for function_layer in function_layers:
                original_implementation = function_layer(original_implementation)
            return original_implementation

        config.override.functions = fn_override

        # config.override.functions = function_layers[0]
        # for function_layer in function_layers[1:]:
        #     config.override.functions = function_layer(config.override.functions)

    if len(api_layers) > 0 and recipe_id != "accountlinking":
        # config.override.apis = api_layers[0]
        # for api_layer in api_layers[1:]:
        #     config.override.apis = api_layer(config.override.apis)
        def api_override(original_implementation: Any) -> Any:
            for api_layer in reversed(api_layers):
                # for api_layer in api_layers:
                original_implementation = api_layer(original_implementation)
            return original_implementation

        config.override.apis = api_override

    return config
