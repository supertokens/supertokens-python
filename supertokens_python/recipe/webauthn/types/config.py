# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Protocol, TypeVar, Union, runtime_checkable

from supertokens_python.framework import BaseRequest
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.types.base import UserContext

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import (
        APIInterface,
        TypeWebauthnEmailDeliveryInput,
    )
    from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface

InterfaceType = TypeVar("InterfaceType")
"""Generic Type for use in `InterfaceOverride`"""


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
        request: Optional[BaseRequest],
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
        request: Optional[BaseRequest],
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


# NOTE: Using dataclasses for these classes since validation is not required
@dataclass
class OverrideConfig:
    """
    `WebauthnConfig.override`
    """

    functions: Optional[InterfaceOverride[RecipeInterface]] = None
    apis: Optional[InterfaceOverride[APIInterface]] = None


@dataclass
class WebauthnConfig:
    get_relying_party_id: Optional[Union[str, GetRelyingPartyId]] = None
    get_relying_party_name: Optional[Union[str, GetRelyingPartyName]] = None
    get_origin: Optional[GetOrigin] = None
    email_delivery: Optional[EmailDeliveryConfig[TypeWebauthnEmailDeliveryInput]] = None
    validate_email_address: Optional[ValidateEmailAddress] = None
    override: Optional[OverrideConfig] = None


@dataclass
class NormalisedWebauthnConfig:
    get_relying_party_id: NormalisedGetRelyingPartyId
    get_relying_party_name: NormalisedGetRelyingPartyName
    get_origin: NormalisedGetOrigin
    get_email_delivery_config: NormalisedGetEmailDeliveryConfig
    validate_email_address: NormalisedValidateEmailAddress
    override: OverrideConfig


@dataclass
class WebauthnIngredients:
    email_delivery: Optional[
        EmailDeliveryIngredient[TypeWebauthnEmailDeliveryInput]
    ] = None
