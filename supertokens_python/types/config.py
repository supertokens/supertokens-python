from typing import Callable, Generic, Optional, TypeVar

from supertokens_python.types.recipe import BaseAPIInterface, BaseRecipeInterface
from supertokens_python.types.response import CamelCaseBaseModel
from supertokens_python.types.utils import UseDefaultIfNone

T = TypeVar("T")

"""Generic Type for use in `InterfaceOverride`"""
FunctionInterfaceType = TypeVar("FunctionInterfaceType", bound=BaseRecipeInterface)
"""Generic Type for use in `FunctionOverrideConfig`"""
APIInterfaceType = TypeVar("APIInterfaceType", bound=BaseAPIInterface)
"""Generic Type for use in `APIOverrideConfig`"""


InterfaceOverride = Callable[[T], T]


class BaseOverrideConfigWithoutAPI(CamelCaseBaseModel, Generic[FunctionInterfaceType]):
    """Base class for input override config without API overrides."""

    functions: UseDefaultIfNone[Optional[InterfaceOverride[FunctionInterfaceType]]] = (
        lambda original_implementation: original_implementation
    )


class BaseNormalisedOverrideConfigWithoutAPI(
    CamelCaseBaseModel, Generic[FunctionInterfaceType]
):
    """Base class for normalized override config without API overrides."""

    functions: InterfaceOverride[FunctionInterfaceType] = (
        lambda original_implementation: original_implementation
    )


class BaseOverrideConfig(
    BaseOverrideConfigWithoutAPI[FunctionInterfaceType],
    Generic[FunctionInterfaceType, APIInterfaceType],
):
    """Base class for input override config with API overrides."""

    apis: UseDefaultIfNone[Optional[InterfaceOverride[APIInterfaceType]]] = (
        lambda original_implementation: original_implementation
    )


class BaseNormalisedOverrideConfig(
    BaseNormalisedOverrideConfigWithoutAPI[FunctionInterfaceType],
    Generic[FunctionInterfaceType, APIInterfaceType],
):
    """Base class for normalized override config with API overrides."""

    apis: InterfaceOverride[APIInterfaceType] = (
        lambda original_implementation: original_implementation
    )


class BaseConfigWithoutAPIOverride(CamelCaseBaseModel, Generic[FunctionInterfaceType]):
    """Base class for input config of a Recipe without API overrides."""

    override: Optional[BaseOverrideConfigWithoutAPI[FunctionInterfaceType]] = None


class BaseNormalisedConfigWithoutAPIOverride(
    CamelCaseBaseModel, Generic[FunctionInterfaceType]
):
    """Base class for normalized config of a Recipe without API overrides."""

    override: BaseNormalisedOverrideConfigWithoutAPI[FunctionInterfaceType]


class BaseConfig(CamelCaseBaseModel, Generic[FunctionInterfaceType, APIInterfaceType]):
    """Base class for input config of a Recipe with API overrides."""

    override: Optional[BaseOverrideConfig[FunctionInterfaceType, APIInterfaceType]] = (
        None
    )


class BaseNormalisedConfig(
    CamelCaseBaseModel, Generic[FunctionInterfaceType, APIInterfaceType]
):
    """Base class for normalized config of a Recipe with API overrides."""

    override: BaseNormalisedOverrideConfig[FunctionInterfaceType, APIInterfaceType]
