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
from typing import TYPE_CHECKING, Any, Dict, Union, Callable, Awaitable, Optional, List

from supertokens_python.types import APIResponse, GeneralErrorResponse

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.thirdparty.provider import (
        ProviderConfig,
        ProviderInput,
    )
    from .utils import MultitenancyConfig


class TenantConfig:
    def __init__(
        self,
        email_password_enabled: Union[bool, None] = None,
        passwordless_enabled: Union[bool, None] = None,
        third_party_enabled: Union[bool, None] = None,
        core_config: Union[Dict[str, Any], None] = None,
    ):
        self.email_password_enabled = email_password_enabled
        self.passwordless_enabled = passwordless_enabled
        self.third_party_enabled = third_party_enabled
        self.core_config = core_config

    def to_json(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        if self.email_password_enabled is not None:
            res["emailPasswordEnabled"] = self.email_password_enabled
        if self.passwordless_enabled is not None:
            res["passwordlessEnabled"] = self.passwordless_enabled
        if self.third_party_enabled is not None:
            res["thirdPartyEnabled"] = self.third_party_enabled
        if self.core_config is not None:
            res["coreConfig"] = self.core_config
        return res


class CreateOrUpdateTenantOkResult:
    status = "OK"

    def __init__(self, created_new: bool):
        self.created_new = created_new


class DeleteTenantOkResult:
    status = "OK"

    def __init__(self, did_exist: bool):
        self.did_exist = did_exist


class EmailPasswordConfig:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def to_json(self):
        return {"enabled": self.enabled}


class PasswordlessConfig:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def to_json(self):
        return {"enabled": self.enabled}


class ThirdPartyConfig:
    def __init__(self, enabled: bool, providers: List[ProviderConfig]):
        self.enabled = enabled
        self.providers = providers

    def to_json(self):
        return {
            "enabled": self.enabled,
            "providers": [provider.to_json() for provider in self.providers],
        }


class TenantConfigResponse:
    def __init__(
        self,
        emailpassword: EmailPasswordConfig,
        passwordless: PasswordlessConfig,
        third_party: ThirdPartyConfig,
        core_config: Dict[str, Any],
    ):
        self.emailpassword = emailpassword
        self.passwordless = passwordless
        self.third_party = third_party
        self.core_config = core_config


class GetTenantOkResult(TenantConfigResponse):
    status = "OK"


class ListAllTenantsItem(TenantConfigResponse):
    def __init__(
        self,
        tenant_id: str,
        emailpassword: EmailPasswordConfig,
        passwordless: PasswordlessConfig,
        third_party: ThirdPartyConfig,
        core_config: Dict[str, Any],
    ):
        super().__init__(emailpassword, passwordless, third_party, core_config)
        self.tenant_id = tenant_id

    def to_json(self):
        res = {
            "tenantId": self.tenant_id,
            "emailPassword": self.emailpassword.to_json(),
            "passwordless": self.passwordless.to_json(),
            "thirdParty": self.third_party.to_json(),
            "coreConfig": self.core_config,
        }

        return res


class ListAllTenantsOkResult:
    status = "OK"

    def __init__(self, tenants: List[ListAllTenantsItem]):
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
        config: Optional[TenantConfig],
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
    ) -> Optional[GetTenantOkResult]:
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
        user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        AssociateUserToTenantOkResult,
        AssociateUserToTenantUnknownUserIdError,
        AssociateUserToTenantEmailAlreadyExistsError,
        AssociateUserToTenantPhoneNumberAlreadyExistsError,
        AssociateUserToTenantThirdPartyUserAlreadyExistsError,
    ]:
        pass

    @abstractmethod
    async def dissociate_user_from_tenant(
        self,
        tenant_id: str,
        user_id: str,
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
    ):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation
        self.static_third_party_providers = static_third_party_providers


class ThirdPartyProvider:
    def __init__(
        self, id: str, name: Optional[str]
    ):  # pylint: disable=redefined-builtin
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
    ):
        self.status = "OK"
        self.email_password = email_password
        self.passwordless = passwordless
        self.third_party = third_party

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "emailPassword": self.email_password.to_json(),
            "passwordless": self.passwordless.to_json(),
            "thirdParty": self.third_party.to_json(),
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
