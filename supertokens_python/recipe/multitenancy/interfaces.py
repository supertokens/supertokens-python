# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Union

from supertokens_python.types import RecipeUserId
from supertokens_python.types.response import APIResponse, GeneralErrorResponse

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.thirdparty.provider import (
        ProviderConfig,
        ProviderInput,
    )

    from .utils import MultitenancyConfig


class TenantConfig:
    # pylint: disable=dangerous-default-value
    def __init__(
        self,
        tenant_id: str = "",
        third_party_providers: List[ProviderConfig] = [],
        core_config: Dict[str, Any] = {},
        first_factors: Optional[List[str]] = None,
        required_secondary_factors: Optional[List[str]] = None,
    ):
        self.tenant_id = tenant_id
        self.core_config = core_config
        self.first_factors = first_factors
        self.required_secondary_factors = required_secondary_factors
        self.third_party_providers = third_party_providers

    @staticmethod
    def from_json(json: Dict[str, Any]) -> TenantConfig:
        return TenantConfig(
            tenant_id=json.get("tenantId", ""),
            third_party_providers=[
                ProviderConfig.from_json(provider)
                for provider in json.get("thirdPartyProviders", [])
            ],
            core_config=json.get("coreConfig", {}),
            first_factors=json.get("firstFactors", []),
            required_secondary_factors=json.get("requiredSecondaryFactors", []),
        )

    def to_json(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        res["tenantId"] = self.tenant_id
        res["thirdPartyProviders"] = [
            provider.to_json() for provider in self.third_party_providers
        ]
        res["firstFactors"] = self.first_factors
        res["requiredSecondaryFactors"] = self.required_secondary_factors
        res["coreConfig"] = self.core_config
        return res


class TenantConfigCreateOrUpdate:
    # pylint: disable=dangerous-default-value
    def __init__(
        self,
        core_config: Dict[str, Any] = {},
        first_factors: Optional[List[str]] = [
            "NO_CHANGE"
        ],  # A default value here means that if the user does not set this, it will not make any change in the core. This is different from None,
        # which means that the user wants to unset it in the core.
        required_secondary_factors: Optional[List[str]] = [
            "NO_CHANGE"
        ],  # A default value here means that if the user does not set this, it will not make any change in the core. This is different from None,
        # which means that the user wants to unset it in the core.
    ):
        self.core_config = core_config
        self._first_factors = first_factors
        self._required_secondary_factors = required_secondary_factors

    def is_first_factors_unchanged(self) -> bool:
        return self._first_factors == ["NO_CHANGE"]

    def is_required_secondary_factors_unchanged(self) -> bool:
        return self._required_secondary_factors == ["NO_CHANGE"]

    def get_first_factors_for_update(self) -> Optional[List[str]]:
        if self._first_factors == ["NO_CHANGE"]:
            raise Exception(
                "First check if the value of first_factors is not NO_CHANGE"
            )
        return self._first_factors

    def get_required_secondary_factors_for_update(self) -> Optional[List[str]]:
        if self._required_secondary_factors == ["NO_CHANGE"]:
            raise Exception(
                "First check if the value of required_secondary_factors is not NO_CHANGE"
            )
        return self._required_secondary_factors

    @staticmethod
    def from_json(json: Dict[str, Any]) -> TenantConfigCreateOrUpdate:
        return TenantConfigCreateOrUpdate(
            core_config=json.get("coreConfig", {}),
            first_factors=json.get("firstFactors", ["NO_CHANGE"]),
            required_secondary_factors=json.get(
                "requiredSecondaryFactors", ["NO_CHANGE"]
            ),
        )


class CreateOrUpdateTenantOkResult:
    status = "OK"

    def __init__(self, created_new: bool):
        self.created_new = created_new


class DeleteTenantOkResult:
    status = "OK"

    def __init__(self, did_exist: bool):
        self.did_exist = did_exist


class ListAllTenantsOkResult:
    status = "OK"

    def __init__(self, tenants: List[TenantConfig]):
        self.tenants = tenants


class CreateOrUpdateThirdPartyConfigOkResult:
    status = "OK"

    def __init__(self, created_new: bool):
        self.created_new = created_new


class DeleteThirdPartyConfigOkResult:
    status = "OK"

    def __init__(self, did_config_exist: bool):
        self.did_config_exist = did_config_exist


class AssociateUserToTenantOkResult:
    status = "OK"

    def __init__(self, was_already_associated: bool):
        self.was_already_associated = was_already_associated


class AssociateUserToTenantUnknownUserIdError:
    status = "UNKNOWN_USER_ID_ERROR"


class AssociateUserToTenantEmailAlreadyExistsError:
    status = "EMAIL_ALREADY_EXISTS_ERROR"


class AssociateUserToTenantPhoneNumberAlreadyExistsError:
    status = "PHONE_NUMBER_ALREADY_EXISTS_ERROR"


class AssociateUserToTenantThirdPartyUserAlreadyExistsError:
    status = "THIRD_PARTY_USER_ALREADY_EXISTS_ERROR"


class AssociateUserToTenantNotAllowedError:
    status = "ASSOCIATION_NOT_ALLOWED_ERROR"

    def __init__(self, reason: str):
        self.status = "ASSOCIATION_NOT_ALLOWED_ERROR"
        self.reason = reason


class DisassociateUserFromTenantOkResult:
    status = "OK"

    def __init__(self, was_associated: bool):
        self.was_associated = was_associated


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_tenant_id(
        self, tenant_id_from_frontend: str, user_context: Dict[str, Any]
    ) -> str:
        pass

    @abstractmethod
    async def create_or_update_tenant(
        self,
        tenant_id: str,
        config: Optional[TenantConfigCreateOrUpdate],
        user_context: Dict[str, Any],
    ) -> CreateOrUpdateTenantOkResult:
        pass

    @abstractmethod
    async def delete_tenant(
        self, tenant_id: str, user_context: Dict[str, Any]
    ) -> DeleteTenantOkResult:
        pass

    @abstractmethod
    async def get_tenant(
        self, tenant_id: str, user_context: Dict[str, Any]
    ) -> Optional[TenantConfig]:
        pass

    @abstractmethod
    async def list_all_tenants(
        self, user_context: Dict[str, Any]
    ) -> ListAllTenantsOkResult:
        pass

    # third party provider management
    @abstractmethod
    async def create_or_update_third_party_config(
        self,
        tenant_id: str,
        config: ProviderConfig,
        skip_validation: Optional[bool],
        user_context: Dict[str, Any],
    ) -> CreateOrUpdateThirdPartyConfigOkResult:
        pass

    @abstractmethod
    async def delete_third_party_config(
        self,
        tenant_id: str,
        third_party_id: str,
        user_context: Dict[str, Any],
    ) -> DeleteThirdPartyConfigOkResult:
        pass

    # user tenant association
    @abstractmethod
    async def associate_user_to_tenant(
        self,
        tenant_id: str,
        recipe_user_id: RecipeUserId,
        user_context: Dict[str, Any],
    ) -> Union[
        AssociateUserToTenantOkResult,
        AssociateUserToTenantUnknownUserIdError,
        AssociateUserToTenantEmailAlreadyExistsError,
        AssociateUserToTenantPhoneNumberAlreadyExistsError,
        AssociateUserToTenantThirdPartyUserAlreadyExistsError,
        AssociateUserToTenantNotAllowedError,
    ]:
        pass

    @abstractmethod
    async def disassociate_user_from_tenant(
        self,
        tenant_id: str,
        recipe_user_id: RecipeUserId,
        user_context: Dict[str, Any],
    ) -> DisassociateUserFromTenantOkResult:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: MultitenancyConfig,
        recipe_implementation: RecipeInterface,
        static_third_party_providers: List[ProviderInput],
        all_available_first_factors: List[str],
        static_first_factors: Optional[List[str]],
    ):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation
        self.static_third_party_providers = static_third_party_providers
        self.static_first_factors = static_first_factors
        self.all_available_first_factors = all_available_first_factors


class ThirdPartyProvider:
    def __init__(self, id: str, name: Optional[str]):  # pylint: disable=redefined-builtin
        self.id = id
        self.name = name

    def to_json(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
        }


class LoginMethodEmailPassword:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def to_json(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
        }


class LoginMethodPasswordless:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def to_json(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
        }


class LoginMethodWebauthn:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def to_json(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
        }


class LoginMethodThirdParty:
    def __init__(self, enabled: bool, providers: List[ThirdPartyProvider]):
        self.enabled = enabled
        self.providers = providers

    def to_json(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "providers": [provider.to_json() for provider in self.providers],
        }


class LoginMethodsGetOkResult(APIResponse):
    def __init__(
        self,
        email_password: LoginMethodEmailPassword,
        passwordless: LoginMethodPasswordless,
        third_party: LoginMethodThirdParty,
        webauthn: LoginMethodWebauthn,
        first_factors: List[str],
    ):
        self.status = "OK"
        self.email_password = email_password
        self.passwordless = passwordless
        self.third_party = third_party
        self.webauthn = webauthn
        self.first_factors = first_factors

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "emailPassword": self.email_password.to_json(),
            "passwordless": self.passwordless.to_json(),
            "thirdParty": self.third_party.to_json(),
            "webauthn": self.webauthn.to_json(),
            "firstFactors": self.first_factors,
        }


class APIInterface(ABC):
    def __init__(self):
        self.disable_login_methods_get = False

    @abstractmethod
    async def login_methods_get(
        self,
        tenant_id: str,
        client_type: Optional[str],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[LoginMethodsGetOkResult, GeneralErrorResponse]:
        pass


TypeGetAllowedDomainsForTenantId = Callable[
    [str, Dict[str, Any]], Awaitable[Optional[List[str]]]
]
