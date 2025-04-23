from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, TypeVar

from typing_extensions import TypeAlias

from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.webauthn.interfaces.api import ApiInterface
from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface

# TODO: Should `UserContext` be optional to handle `None` and init with `{}`?
# TODO: Make this generic and re-use across codebase?
UserContext: TypeAlias = Dict[str, Any]


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


class WebauthnConfig:
    get_relying_party_id: GetRelyingPartyId
    get_relying_party_name: GetRelyingPartyName
    get_origin: GetOrigin
    get_email_delivery_config: GetEmailDeliveryConfig
    validate_email_address: ValidateEmailAddress
    override: OverrideConfig

    def __init__(
        self,
        *,
        get_relying_party_id: GetRelyingPartyId,
        get_relying_party_name: GetRelyingPartyName,
        get_origin: GetOrigin,
        get_email_delivery_config: GetEmailDeliveryConfig,
        validate_email_address: ValidateEmailAddress,
        override: OverrideConfig,
    ):
        self.get_relying_party_id = get_relying_party_id
        self.get_relying_party_name = get_relying_party_name
        self.get_origin = get_origin
        self.get_email_delivery_config = get_email_delivery_config
        self.validate_email_address = validate_email_address
        self.override = override
