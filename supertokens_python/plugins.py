from collections import deque
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    TypeVar,
    Union,
    cast,
    runtime_checkable,
)

from typing_extensions import Protocol

from supertokens_python.constants import VERSION
from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse
from supertokens_python.logger import log_debug_message
from supertokens_python.post_init_callbacks import PostSTInitCallbacks
from supertokens_python.recipe.accountlinking.types import AccountLinkingConfig
from supertokens_python.recipe.dashboard.utils import DashboardConfig
from supertokens_python.recipe.emailpassword.utils import EmailPasswordConfig
from supertokens_python.recipe.emailverification.utils import (
    EmailVerificationConfig,
)
from supertokens_python.recipe.jwt.utils import JWTConfig
from supertokens_python.recipe.multifactorauth.types import MultiFactorAuthConfig
from supertokens_python.recipe.multitenancy.utils import MultitenancyConfig
from supertokens_python.recipe.oauth2provider.utils import OAuth2ProviderConfig
from supertokens_python.recipe.openid.utils import OpenIdConfig
from supertokens_python.recipe.passwordless.utils import PasswordlessConfig
from supertokens_python.recipe.session.interfaces import (
    SessionClaimValidator,
    SessionContainer,
)
from supertokens_python.recipe.session.utils import SessionConfig
from supertokens_python.recipe.thirdparty.utils import ThirdPartyConfig
from supertokens_python.recipe.totp.types import TOTPConfig
from supertokens_python.recipe.usermetadata.utils import UserMetadataConfig
from supertokens_python.recipe.userroles.utils import UserRolesConfig
from supertokens_python.recipe.webauthn.types.config import WebauthnConfig
from supertokens_python.types import MaybeAwaitable
from supertokens_python.types.base import UserContext
from supertokens_python.types.config import (
    BaseConfig,
    BaseConfigWithoutAPIOverride,
    BaseOverrideConfig,
    BaseOverrideConfigWithoutAPI,
)
from supertokens_python.types.recipe import BaseAPIInterface, BaseRecipeInterface
from supertokens_python.types.response import CamelCaseBaseModel

if TYPE_CHECKING:
    from supertokens_python.supertokens import SupertokensPublicConfig

T = TypeVar(
    "T",
    bound=Union[
        AccountLinkingConfig,
        DashboardConfig,
        EmailPasswordConfig,
        EmailVerificationConfig,
        JWTConfig,
        MultiFactorAuthConfig,
        MultitenancyConfig,
        OAuth2ProviderConfig,
        OpenIdConfig,
        PasswordlessConfig,
        SessionConfig,
        ThirdPartyConfig,
        TOTPConfig,
        UserMetadataConfig,
        UserRolesConfig,
        WebauthnConfig,
    ],
)

RecipeInterfaceType = TypeVar("RecipeInterfaceType", bound=BaseRecipeInterface)
APIInterfaceType = TypeVar("APIInterfaceType", bound=BaseAPIInterface)


class RecipeInitRequiredFunction(Protocol):
    def __call__(self, sdk_version: str) -> bool: ...


class RecipePluginOverride:
    functions: Optional[Callable[[BaseRecipeInterface], BaseRecipeInterface]]
    apis: Optional[Callable[[BaseAPIInterface], BaseAPIInterface]]
    config: Optional[Callable[[Any], Any]]
    recipe_init_required: Optional[Union[bool, RecipeInitRequiredFunction]] = None


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
    session_required: bool
    anti_csrf_check: Optional[bool] = None
    check_database: bool
    override_global_claim_validators: Optional[
        OverrideGlobalClaimValidatorsFunction
    ] = None


class PluginRouteHandler(CamelCaseBaseModel):
    method: str
    path: str
    handler: PluginRouteHandlerHandlerFunction
    verify_session_options: Optional[VerifySessionOptions]


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
    route_handlers: List[PluginRouteHandler]


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
    override_map: Optional[Dict[str, RecipePluginOverride]] = None
    route_handlers: Optional[
        Union[List[PluginRouteHandler], PluginRouteHandlerFunction]
    ] = None
    config: Optional[PluginConfig] = None

    def get_dependencies(
        self,
        public_config: "SupertokensPublicConfig",
        plugins_above: List["SuperTokensPlugin"],
        sdk_version: str,
    ):
        """
        Pre-order DFS traversal to get all dependencies of a plugin.
        """

        def recurse_deps(
            plugin: SuperTokensPlugin,
            deps: Optional[List[SuperTokensPlugin]] = None,
            visited: Optional[Set[str]] = None,
        ) -> List[SuperTokensPlugin]:
            if deps is None:
                deps = []

            if visited is None:
                visited = set()

            if plugin.id in visited:
                return deps
            visited.add(plugin.id)

            if plugin.dependencies is not None:
                # Get all dependencies of the plugin
                dep_result = plugin.dependencies(
                    config=public_config,
                    plugins_above=[
                        SuperTokensPublicPlugin.from_plugin(plugin)
                        for plugin in plugins_above
                    ],
                    sdk_version=sdk_version,
                )

                # Errors fall through
                if isinstance(dep_result, PluginDependenciesErrorResponse):
                    raise Exception(dep_result.message)

                # Recurse through all dependencies and add the resultant plugins to the list
                # Pre-order DFS traversal
                for dep_plugin in dep_result.plugins_to_add:
                    recurse_deps(dep_plugin, deps)

            # Add the current plugin and mark it as visited
            deps.append(plugin)

            return deps

        return recurse_deps(self)


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


def apply_plugins(
    recipe_id: str,
    config: T,
    plugins: List[OverrideMap],
) -> T:
    if not isinstance(config, (BaseConfig, BaseConfigWithoutAPIOverride)):  # type: ignore
        raise TypeError(
            f"Expected config to be an instance of BaseConfig or BaseConfigWithoutAPIOverride. {recipe_id=} {config=}"
        )

    def default_fn_override(
        original_implementation: RecipeInterfaceType,
    ) -> RecipeInterfaceType:
        return original_implementation

    def default_api_override(
        original_implementation: APIInterfaceType,
    ) -> APIInterfaceType:
        return original_implementation

    if config.override is None:
        if isinstance(config, BaseConfigWithoutAPIOverride):
            config.override = BaseOverrideConfigWithoutAPI()
        else:
            config.override = BaseOverrideConfig()  # type: ignore

    function_overrides = getattr(config.override, "functions", default_fn_override)
    api_overrides = getattr(config.override, "apis", default_api_override)

    function_layers: deque[Any] = deque()
    api_layers: deque[Any] = deque()

    # If we have plugins like 4->3->(2, 1) along with a recipe override,
    # we want to load/init them as: override, 2, 1, 3, 4
    # and call them as: override, 4, 3, 2, 1, original
    # Order of 1/2 does not matter since they are independent from each other.

    for plugin in plugins:
        overrides = plugin.get(recipe_id)
        if overrides is not None:
            if overrides.config is not None:
                config = overrides.config(config)

            if overrides.functions is not None:
                function_layers.append(overrides.functions)
            if overrides.apis is not None:
                api_layers.append(overrides.apis)

    if function_overrides is not None:
        function_layers.append(function_overrides)
    if api_overrides is not None:
        api_layers.append(api_overrides)

    # Apply overrides in reverse order of definition
    # Plugins: [plugin1, plugin2] would be applied as [override, plugin2, plugin1, original]
    if len(function_layers) > 0:

        def fn_override(
            original_implementation: RecipeInterfaceType,
        ) -> RecipeInterfaceType:
            # The layers will get called in reversed order
            for function_layer in function_layers:
                original_implementation = function_layer(original_implementation)
            return original_implementation

        config.override.functions = fn_override  # type: ignore

    if (
        len(api_layers) > 0
        # AccountLinking recipe does not have an API implementation, uses `BaseConfigWithoutAPIOverride` as base
        and recipe_id != "accountlinking"
        # `BaseConfig` is the base class for all configs with an API override.
        and isinstance(config, BaseConfig)
    ):

        def api_override(original_implementation: APIInterfaceType) -> APIInterfaceType:
            for api_layer in api_layers:
                original_implementation = api_layer(original_implementation)
            return original_implementation

        config.override.apis = api_override  # type: ignore

    return config


class LoadPluginsResponse(CamelCaseBaseModel):
    public_config: "SupertokensPublicConfig"
    processed_plugins: List[SuperTokensPublicPlugin]
    plugin_route_handlers: List[PluginRouteHandler]
    override_maps: List[OverrideMap]


def load_plugins(
    plugins: List[SuperTokensPlugin], public_config: "SupertokensPublicConfig"
) -> LoadPluginsResponse:
    input_plugin_seen_list: Set[str] = set()
    final_plugin_list: List[SuperTokensPlugin] = []
    plugin_route_handlers: List[PluginRouteHandler] = []

    for plugin in plugins:
        if plugin.id in input_plugin_seen_list:
            log_debug_message(f"Skipping {plugin.id=} as it has already been added")
            continue

        if isinstance(plugin.compatible_sdk_versions, list):
            version_constraints = plugin.compatible_sdk_versions
        else:
            version_constraints = [plugin.compatible_sdk_versions]

        if VERSION not in version_constraints:
            # TODO: Better checks
            raise Exception("Plugin version mismatch")

        # TODO: Overkill, but could topologically sort the plugins based on dependencies
        dependencies = plugin.get_dependencies(
            public_config=public_config,
            plugins_above=final_plugin_list,
            sdk_version=VERSION,
        )
        final_plugin_list.extend(dependencies)
        input_plugin_seen_list.update({dep.id for dep in dependencies})

    processed_plugin_list = [
        SuperTokensPublicPlugin.from_plugin(plugin) for plugin in final_plugin_list
    ]

    for plugin_idx, plugin in enumerate(final_plugin_list):
        # Override the public supertokens config using the config override defined in the plugin
        if plugin.config is not None:
            public_config = plugin.config(public_config)

        if plugin.route_handlers is not None:
            handlers: List[PluginRouteHandler] = []

            if callable(plugin.route_handlers):
                handler_result = plugin.route_handlers(
                    config=public_config,
                    all_plugins=processed_plugin_list,
                    sdk_version=VERSION,
                )
                if isinstance(handler_result, PluginRouteHandlerFunctionErrorResponse):
                    raise Exception(handler_result.message)

                handlers = handler_result.route_handlers
            else:
                handlers = plugin.route_handlers

            plugin_route_handlers.extend(handlers)

        if plugin.init is not None:

            def callback_factory():
                # This has to be part of the factory to ensure we pick up the correct plugin
                init_fn = cast(SuperTokensPluginInit, plugin.init)
                idx = plugin_idx

                def callback():
                    init_fn(
                        config=public_config,
                        all_plugins=processed_plugin_list,
                        sdk_version=VERSION,
                    )
                    processed_plugin_list[idx].initialized = True

                return callback

            PostSTInitCallbacks.add_post_init_callback(callback_factory())

    override_maps = [
        plugin.override_map
        for plugin in final_plugin_list
        if plugin.override_map is not None
    ]

    return LoadPluginsResponse(
        public_config=public_config,
        processed_plugins=processed_plugin_list,
        plugin_route_handlers=plugin_route_handlers,
        override_maps=override_maps,
    )
