from typing import Any, List, Optional

from pydantic import Field
from supertokens_python.supertokens import (
    AppInfo,
)
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
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


class PluginTestOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    test_property: List[str] = Field(default_factory=lambda: ["original"])


class PluginTestConfig(
    PluginTestOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, PluginTestOverrideableConfig],
):
    def to_overrideable_config(self) -> PluginTestOverrideableConfig:
        """Create a `PluginTestOverrideableConfig` from the current config."""
        return PluginTestOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: PluginTestOverrideableConfig,
    ) -> "PluginTestConfig":
        """
        Create a `PluginTestConfig` from a `PluginTestOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return PluginTestConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalizedPluginTestConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    test_property: List[str]


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
