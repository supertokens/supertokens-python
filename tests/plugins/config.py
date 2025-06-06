from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Optional,
    Protocol,
    TypeVar,
    runtime_checkable,
)

from supertokens_python.supertokens import (
    AppInfo,
)

if TYPE_CHECKING:
    from .api_implementation import APIInterface
    from .recipe_implementation import RecipeInterface

InterfaceType = TypeVar("InterfaceType")
"""Generic Type for use in `InterfaceOverride`"""


@runtime_checkable
class InterfaceOverride(Protocol[InterfaceType]):
    """
    Callable signature for `WebauthnConfig.override.*`.
    """

    def __call__(
        self,
        original_implementation: InterfaceType,
    ) -> InterfaceType: ...


# NOTE: Using dataclasses for these classes since validation is not required
@dataclass
class OverrideConfig:
    """
    `WebauthnConfig.override`
    """

    functions: Optional[InterfaceOverride["RecipeInterface"]] = None
    apis: Optional[InterfaceOverride["APIInterface"]] = None
    config: Optional[InterfaceOverride[Any]] = None


@dataclass
class NormalizedPluginTestConfig:
    override: OverrideConfig


@dataclass
class PluginTestConfig:
    override: Optional[OverrideConfig] = None


def validate_and_normalise_user_input(
    config: Optional[PluginTestConfig], app_info: AppInfo
) -> NormalizedPluginTestConfig:
    if config is None:
        config = PluginTestConfig()

    if config.override is None:
        override = OverrideConfig()
    else:
        override = OverrideConfig(
            functions=config.override.functions,
            apis=config.override.apis,
        )

    return NormalizedPluginTestConfig(override=override)
