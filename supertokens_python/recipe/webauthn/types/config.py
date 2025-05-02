from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Protocol, TypeVar, runtime_checkable

from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.types.response import CamelCaseBaseModel

# These imports are only required for type-hints, not for runtime use
# Prevents circular import errors
if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import ApiInterface

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
class GetRelyingPartyName(Protocol):
    """
    Callable signature for `WebauthnConfig.get_relying_party_name`.
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
class GetEmailDeliveryConfig(Protocol):
    """
    Callable signature for `WebauthnConfig.get_email_delivery_config`.
    """

    # TODO: implement return types
    async def __call__(
        self, is_in_serverless_env: bool
    ):  # -> EmailDeliveryTypeInputWithService<TypeWebauthnEmailDeliveryInput>
        ...


@runtime_checkable
class ValidateEmailAddress(Protocol):
    """
    Callable signature for `WebauthnConfig.validate_email_address`.
    """

    async def __call__(
        self, *, email: str, tenant_id: str, user_context: UserContext
    ) -> Optional[str]: ...


@runtime_checkable
class InterfaceOverride(Protocol[InterfaceType]):
    """
    Callable signature for `WebauthnConfig.override.*`.
    """

    async def __call__(
        self,
        original_implementation: InterfaceType,
    ) -> InterfaceType: ...


class OverrideConfig:
    """
    `WebauthnConfig.override`
    """

    functions: Optional[InterfaceOverride[RecipeInterface]]
    apis: Optional[InterfaceOverride[ApiInterface]]

    async def __init__(
        self,
        *,
        functions: Optional[InterfaceOverride[RecipeInterface]] = None,
        apis: Optional[InterfaceOverride[ApiInterface]] = None,
    ):
        self.functions = functions
        self.apis = apis


# TODO: Figure out if we want/need pydantic here. Validation errors might be tough to resolve
class WebauthnConfig(CamelCaseBaseModel):
    get_relying_party_id: GetRelyingPartyId
    get_relying_party_name: GetRelyingPartyName
    get_origin: GetOrigin
    get_email_delivery_config: GetEmailDeliveryConfig
    validate_email_address: ValidateEmailAddress
    override: OverrideConfig
