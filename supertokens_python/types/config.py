from typing import Callable, Generic, Optional, TypeVar, Union

from supertokens_python.types.recipe import BaseAPIInterface, BaseRecipeInterface
from supertokens_python.types.response import CamelCaseBaseModel

InterfaceType = TypeVar(
    "InterfaceType", bound=Union[BaseRecipeInterface, BaseAPIInterface]
)
"""Generic Type for use in `InterfaceOverride`"""
FunctionInterfaceType = TypeVar("FunctionInterfaceType", bound=BaseRecipeInterface)
"""Generic Type for use in `FunctionOverrideConfig`"""
APIInterfaceType = TypeVar("APIInterfaceType", bound=BaseAPIInterface)
"""Generic Type for use in `APIOverrideConfig`"""


InterfaceOverride = Callable[[InterfaceType], InterfaceType]

# @runtime_checkable
# class InterfaceOverride(Protocol[InterfaceType]):
#     """
#     Callable signature for `<Config>.override.*`.
#     """

#     def __call__(
#         self,
#         original_implementation: InterfaceType,
#     ) -> InterfaceType: ...


class BaseInputOverrideConfigWithoutAPI(
    CamelCaseBaseModel, Generic[FunctionInterfaceType]
):
    """Base class for input override config without API overrides."""

    functions: Optional[InterfaceOverride[FunctionInterfaceType]] = None


class BaseOverrideConfigWithoutAPI(CamelCaseBaseModel, Generic[FunctionInterfaceType]):
    """Base class for normalized override config without API overrides."""

    functions: InterfaceOverride[FunctionInterfaceType] = (
        lambda original_implementation: original_implementation
    )


class BaseInputOverrideConfig(
    BaseInputOverrideConfigWithoutAPI[FunctionInterfaceType],
    Generic[FunctionInterfaceType, APIInterfaceType],
):
    """Base class for input override config with API overrides."""

    apis: Optional[InterfaceOverride[APIInterfaceType]] = None


class BaseOverrideConfig(
    BaseOverrideConfigWithoutAPI[FunctionInterfaceType],
    Generic[FunctionInterfaceType, APIInterfaceType],
):
    """Base class for normalized override config with API overrides."""

    apis: InterfaceOverride[APIInterfaceType] = (
        lambda original_implementation: original_implementation
    )


class BaseInputConfigWithoutAPIOverride(
    CamelCaseBaseModel, Generic[FunctionInterfaceType]
):
    """Base class for input config of a Recipe without API overrides."""

    override: Optional[BaseInputOverrideConfigWithoutAPI[FunctionInterfaceType]] = None


class BaseConfigWithoutAPIOverride(CamelCaseBaseModel, Generic[FunctionInterfaceType]):
    """Base class for normalized config of a Recipe without API overrides."""

    override: BaseOverrideConfigWithoutAPI[FunctionInterfaceType]


class BaseInputConfig(
    CamelCaseBaseModel, Generic[FunctionInterfaceType, APIInterfaceType]
):
    """Base class for input config of a Recipe with API overrides."""

    override: Optional[
        BaseInputOverrideConfig[FunctionInterfaceType, APIInterfaceType]
    ] = None


class BaseConfig(CamelCaseBaseModel, Generic[FunctionInterfaceType, APIInterfaceType]):
    """Base class for normalized config of a Recipe with API overrides."""

    override: BaseOverrideConfig[FunctionInterfaceType, APIInterfaceType]
