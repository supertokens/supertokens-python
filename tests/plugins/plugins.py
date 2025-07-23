from typing import Any, List, Optional, Union

from supertokens_python.constants import VERSION
from supertokens_python.plugins import (
    OverrideMap,
    PluginDependenciesOkResponse,
    RecipePluginOverride,
    SuperTokensPlugin,
    SuperTokensPluginDependencies,
    SuperTokensPublicPlugin,
)
from supertokens_python.supertokens import SupertokensPublicConfig

from .api_implementation import APIInterface
from .config import PluginTestConfig
from .recipe import PluginTestRecipe
from .recipe_implementation import RecipeInterface


def function_override_factory(identifier: str):
    def function_override(original_implementation: RecipeInterface) -> RecipeInterface:
        og_sign_in = original_implementation.sign_in

        def new_sign_in(message: str, stack: List[str]):
            stack.append(identifier)
            return og_sign_in(message, stack)

        original_implementation.sign_in = new_sign_in
        return original_implementation

    return function_override


def api_override_factory(identifier: str):
    def function_override(original_implementation: APIInterface) -> APIInterface:
        sign_in_post = original_implementation.sign_in_post

        def new_sign_in_post(message: str, stack: List[str]):
            stack.append(identifier)
            return sign_in_post(message, stack)

        original_implementation.sign_in_post = new_sign_in_post
        return original_implementation

    return function_override


def config_override_factory(identifier: str):
    def config_override(original_config: PluginTestConfig) -> PluginTestConfig:
        original_config.test_property.append(identifier)
        return original_config

    return config_override


def init_factory(identifier: str):
    def init(
        config: SupertokensPublicConfig,
        all_plugins: List[SuperTokensPublicPlugin],
        sdk_version: str,
    ):
        PluginTestRecipe.init_calls.append(identifier)

    return init


def dependency_factory(dependencies: Optional[List[SuperTokensPlugin]]):
    if dependencies is None:
        dependencies = []

    def dependency(
        config: SupertokensPublicConfig,
        plugins_above: List[SuperTokensPublicPlugin],
        sdk_version: str,
    ):
        added_plugin_ids = [plugin.id for plugin in plugins_above]
        plugins_to_add = [
            plugin for plugin in dependencies if plugin.id not in added_plugin_ids
        ]
        return PluginDependenciesOkResponse(plugins_to_add=plugins_to_add)

    return dependency


def plugin_factory(
    identifier: str,
    override_functions: bool = False,
    override_apis: bool = False,
    override_config: bool = False,
    deps: Optional[List[SuperTokensPlugin]] = None,
    add_init: bool = False,
):
    override_map_obj: OverrideMap = {PluginTestRecipe.recipe_id: RecipePluginOverride()}

    if override_functions:
        override_map_obj[
            PluginTestRecipe.recipe_id
        ].functions = function_override_factory(identifier)  # type: ignore
    if override_apis:
        override_map_obj[PluginTestRecipe.recipe_id].apis = api_override_factory(
            identifier
        )  # type: ignore

    if override_config:
        override_map_obj[PluginTestRecipe.recipe_id].config = config_override_factory(
            identifier
        )

    init_fn = None
    if add_init:
        init_fn = init_factory(identifier)

    class Plugin(SuperTokensPlugin):
        id: str = identifier
        compatible_sdk_versions: Union[str, List[str]] = [VERSION]
        override_map: Optional[OverrideMap] = override_map_obj
        init: Any = init_fn
        dependencies: Optional[SuperTokensPluginDependencies] = dependency_factory(deps)

    return Plugin()


Plugin1 = plugin_factory(
    "plugin1",
    override_functions=True,
    override_config=True,
    add_init=True,
)
Plugin2 = plugin_factory(
    "plugin2",
    override_functions=True,
    override_config=True,
    add_init=True,
)
Plugin3Dep1 = plugin_factory(
    "plugin3dep1",
    override_functions=True,
    override_config=True,
    deps=[Plugin1],
    add_init=True,
)
Plugin3Dep2_1 = plugin_factory(
    "plugin3dep2_1",
    override_functions=True,
    override_config=True,
    deps=[Plugin2, Plugin1],
    add_init=True,
)
Plugin4Dep1 = plugin_factory(
    "plugin4dep1",
    override_functions=True,
    override_config=True,
    deps=[Plugin1],
    add_init=True,
)
Plugin4Dep2 = plugin_factory(
    "plugin4dep2",
    override_functions=True,
    override_config=True,
    deps=[Plugin2],
    add_init=True,
)
Plugin4Dep3__2_1 = plugin_factory(
    "plugin4dep3__2_1",
    override_functions=True,
    override_config=True,
    deps=[Plugin3Dep2_1],
    add_init=True,
)
