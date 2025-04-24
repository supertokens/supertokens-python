from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, TypeVar

from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.webauthn.interfaces.api import ApiInterface
from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface
from supertokens_python.recipe.webauthn.types.base import UserContext

InterfaceType = TypeVar("InterfaceType")
"""Generic Type for use in `InterfaceOverride`"""


# TODO: Check if we want to use a different naming convention for these types
class GetRelyingPartyId(Protocol):
    """
    Callable signature for `WebauthnConfig.get_relying_party_id`.
    """

    def __call__(
        self,
        *,
        tenant_id: str,
        request: Optional[BaseRequest],
        user_context: UserContext,
    ) -> str: ...


class GetRelyingPartyName(Protocol):
    """
    Callable signature for `WebauthnConfig.get_relying_party_name`.
    """

    def __call__(
        self,
        *,
        tenant_id: str,
        request: Optional[BaseRequest],
        user_context: UserContext,
    ) -> str: ...


class GetOrigin(Protocol):
    """
    Callable signature for `WebauthnConfig.get_origin`.
    """

    def __call__(
        self,
        *,
        tenant_id: str,
        request: BaseRequest,
        user_context: UserContext,
    ) -> str: ...


class GetEmailDeliveryConfig(Protocol):
    """
    Callable signature for `WebauthnConfig.get_email_delivery_config`.
    """

    # TODO: implement return types
    def __call__(
        self, is_in_serverless_env: bool
    ):  # -> EmailDeliveryTypeInputWithService<TypeWebauthnEmailDeliveryInput>
        ...


class ValidateEmailAddress(Protocol):
    """
    Callable signature for `WebauthnConfig.validate_email_address`.
    """

    def __call__(
        self, *, email: str, tenant_id: str, user_context: UserContext
    ) -> Optional[str]: ...


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


@dataclass
class WebauthnConfig:
    get_relying_party_id: GetRelyingPartyId
    get_relying_party_name: GetRelyingPartyName
    get_origin: GetOrigin
    get_email_delivery_config: GetEmailDeliveryConfig
    validate_email_address: ValidateEmailAddress
    override: OverrideConfig
