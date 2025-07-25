from typing import Any, List, Optional

from pydantic import Field
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


class NormalizedPluginTestConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    test_property: List[str]


class PluginTestConfig(BaseConfig[RecipeInterface, APIInterface]):
    test_property: List[str] = Field(default_factory=lambda: ["original"])


class PluginOverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]):
    config: UseDefaultIfNone[Optional[InterfaceOverride[Any]]] = lambda config: config


def validate_and_normalise_user_input(
    config: Optional[PluginTestConfig], app_info: AppInfo
) -> NormalizedPluginTestConfig:
    if config is None:
        config = PluginTestConfig()

    override_config = NormalisedPluginTestOverrideConfig.from_input_config(
        config.override
    )

    return NormalizedPluginTestConfig(
        override=override_config, test_property=config.test_property
    )
