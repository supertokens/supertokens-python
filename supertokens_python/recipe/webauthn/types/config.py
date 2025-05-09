from typing import Optional, Protocol, TypeVar, Union, runtime_checkable

from supertokens_python.framework import BaseRequest
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.webauthn.interfaces.api import (
    ApiInterface,
    TypeWebauthnEmailDeliveryInput,
)
from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.types.response import CamelCaseBaseModel

InterfaceType = TypeVar("InterfaceType")
"""Generic Type for use in `InterfaceOverride`"""


# TODO: Check if we want to use a different naming convention for these types
@runtime_checkable
class GetRelyingPartyId(Protocol):
    """
    Callable signature for `WebauthnConfig.get_relying_party_id`.
    """

    async def __call__(
        self,
        *,
        tenant_id: str,
        request: Optional[BaseRequest],
        user_context: UserContext,
    ) -> str: ...


@runtime_checkable
class NormalisedGetRelyingPartyId(Protocol):
    """
    Callable signature for `WebauthnNormalisedConfig.get_relying_party_id`.
    """

    async def __call__(
        self,
        *,
        tenant_id: str,
        request: Optional[BaseRequest],
        user_context: UserContext,
    ) -> str: ...


@runtime_checkable
class GetRelyingPartyName(Protocol):
    """
    Callable signature for `WebauthnConfig.get_relying_party_name`.
    """

    async def __call__(
        self,
        *,
        tenant_id: str,
        user_context: UserContext,
    ) -> str: ...


@runtime_checkable
class NormalisedGetRelyingPartyName(Protocol):
    """
    Callable signature for `WebauthnNormalisedConfig.get_relying_party_name`.
    """

    async def __call__(
        self,
        *,
        tenant_id: str,
        request: Optional[BaseRequest],
        user_context: UserContext,
    ) -> str: ...


@runtime_checkable
class GetOrigin(Protocol):
    """
    Callable signature for `WebauthnConfig.get_origin`.
    """

    async def __call__(
        self,
        *,
        tenant_id: str,
        request: BaseRequest,
        user_context: UserContext,
    ) -> str: ...


@runtime_checkable
class NormalisedGetOrigin(Protocol):
    """
    Callable signature for `WebauthnNormalisedConfig.get_origin`.
    """

    async def __call__(
        self,
        *,
        tenant_id: str,
        request: BaseRequest,
        user_context: UserContext,
    ) -> str: ...


@runtime_checkable
class GetEmailDeliveryConfig(Protocol):
    """
    Callable signature for `WebauthnNormalisedConfig.get_email_delivery_config`.
    """

    async def __call__(self) -> EmailDeliveryConfig[TypeWebauthnEmailDeliveryInput]: ...


@runtime_checkable
class NormalisedGetEmailDeliveryConfig(Protocol):
    """
    Callable signature for `WebauthnNormalisedConfig.get_email_delivery_config`.
    """

    def __call__(
        self,
    ) -> EmailDeliveryConfigWithService[TypeWebauthnEmailDeliveryInput]: ...


@runtime_checkable
class ValidateEmailAddress(Protocol):
    """
    Callable signature for `WebauthnConfig.validate_email_address`.
    """

    async def __call__(
        self, *, email: str, tenant_id: str, user_context: UserContext
    ) -> Optional[str]: ...


@runtime_checkable
class NormalisedValidateEmailAddress(Protocol):
    """
    Callable signature for `WebauthnNormalisedConfig.validate_email_address`.
    """

    async def __call__(
        self, *, email: str, tenant_id: str, user_context: UserContext
    ) -> Optional[str]: ...


@runtime_checkable
class InterfaceOverride(Protocol[InterfaceType]):
    """
    Callable signature for `WebauthnConfig.override.*`.
    """

    def __call__(
        self,
        original_implementation: InterfaceType,
    ) -> InterfaceType: ...


class OverrideConfig:
    """
    `WebauthnConfig.override`
    """

    functions: Optional[InterfaceOverride[RecipeInterface]]
    apis: Optional[InterfaceOverride[ApiInterface]]

    def __init__(
        self,
        *,
        functions: Optional[InterfaceOverride[RecipeInterface]] = None,
        apis: Optional[InterfaceOverride[ApiInterface]] = None,
    ):
        self.functions = functions
        self.apis = apis


# TODO: Figure out if we want/need pydantic here. Validation errors might be tough to resolve
class WebauthnConfig(CamelCaseBaseModel):
    get_relying_party_id: Optional[Union[str, GetRelyingPartyId]] = None
    get_relying_party_name: Optional[Union[str, GetRelyingPartyName]] = None
    get_origin: Optional[GetOrigin] = None
    email_delivery: Optional[
        EmailDeliveryConfigWithService[TypeWebauthnEmailDeliveryInput]
    ] = None
    validate_email_address: Optional[ValidateEmailAddress] = None
    override: Optional[OverrideConfig] = None


class NormalisedWebauthnConfig(CamelCaseBaseModel):
    get_relying_party_id: NormalisedGetRelyingPartyId
    get_relying_party_name: NormalisedGetRelyingPartyName
    get_origin: NormalisedGetOrigin
    get_email_delivery_config: NormalisedGetEmailDeliveryConfig
    validate_email_address: NormalisedValidateEmailAddress
    override: OverrideConfig


class WebauthnIngredients(CamelCaseBaseModel):
    email_delivery: Optional[
        EmailDeliveryIngredient[TypeWebauthnEmailDeliveryInput]
    ] = None
