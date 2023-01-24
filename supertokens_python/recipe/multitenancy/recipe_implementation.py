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

from typing import TYPE_CHECKING, Optional, Dict, Any
from supertokens_python.recipe.thirdparty.provider import ProviderConfig

from .interfaces import (
    RecipeInterface,
    TenantConfig,
    CreateOrUpdateTenantOkResult,
    DeleteTenantOkResult,
    TenantConfigOkResult,
    ListAllTenantsOkResult,
    CreateOrUpdateThirdPartyConfigOkResult,
    DeleteThirdPartyConfigOkResult,
    ListThirdPartyConfigsForThirdPartyIdOkResult,
)

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

    from .utils import MultitenancyConfig


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, config: MultitenancyConfig):
        super().__init__()
        self.querier = querier
        self.config = config

    async def get_tenant_id(
        self, tenant_id_from_frontend: Optional[str], user_context: Dict[str, Any]
    ) -> Optional[str]:
        pass

    async def create_or_update_tenant(
        self,
        tenant_id: Optional[str],
        config: TenantConfig,
        user_context: Dict[str, Any],
    ) -> CreateOrUpdateTenantOkResult:
        raise NotImplementedError

    async def delete_tenant(
        self, tenant_id: str, user_context: Dict[str, Any]
    ) -> DeleteTenantOkResult:
        raise NotImplementedError

    async def get_tenant_config(
        self, tenant_id: Optional[str], user_context: Dict[str, Any]
    ) -> TenantConfigOkResult:
        raise NotImplementedError

    async def list_all_tenants(
        self, user_context: Dict[str, Any]
    ) -> ListAllTenantsOkResult:
        raise NotImplementedError

    async def create_or_update_third_party_config(
        self, config: ProviderConfig, user_context: Dict[str, Any]
    ) -> CreateOrUpdateThirdPartyConfigOkResult:
        raise NotImplementedError

    async def delete_third_party_config(
        self,
        tenant_id: Optional[str],
        third_party_id: str,
        user_context: Dict[str, Any],
    ) -> DeleteThirdPartyConfigOkResult:
        raise NotImplementedError

    async def list_third_party_configs_for_third_party_id(
        self, third_party_id: str, user_context: Dict[str, Any]
    ) -> ListThirdPartyConfigsForThirdPartyIdOkResult:
        raise NotImplementedError
