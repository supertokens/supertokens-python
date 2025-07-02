from typing import Any, Optional

from supertokens_python.supertokens import (
    AppInfo,
)
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideConfig,
    InterfaceOverride,
)
from supertokens_python.types.utils import UseDefaultIfNone

from .api_implementation import APIInterface
from .recipe_implementation import RecipeInterface

PluginTestOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedPluginTestOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]


class NormalizedPluginTestConfig(
    BaseNormalisedConfig[RecipeInterface, APIInterface]
): ...


class PluginTestConfig(BaseConfig[RecipeInterface, APIInterface]): ...


class PluginOverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]):
    config: UseDefaultIfNone[Optional[InterfaceOverride[Any]]] = lambda config: config


def validate_and_normalise_user_input(
    config: Optional[PluginTestConfig], app_info: AppInfo
) -> NormalizedPluginTestConfig:
    if config is None:
        config = PluginTestConfig()

    override_config = NormalisedPluginTestOverrideConfig()
    if config.override is not None:
        if config.override.functions is not None:
            override_config.functions = config.override.functions

        if config.override.apis is not None:
            override_config.apis = config.override.apis

    return NormalizedPluginTestConfig(override=override_config)
