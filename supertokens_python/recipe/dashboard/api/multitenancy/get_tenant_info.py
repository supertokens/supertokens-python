# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import Any, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python import Supertokens
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.multitenancy.asyncio import get_tenant
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.thirdparty.providers.config_utils import (
    find_and_create_provider_instance,
    merge_providers_from_core_and_static,
)
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions, CoreConfigFieldInfo
from .utils import (
    get_normalised_first_factors_based_on_tenant_config_from_core_and_sdk_init,
)


class ThirdPartyProvider:
    def __init__(self, third_party_id: str, name: str):
        self.third_party_id = third_party_id
        self.name = name

    def to_json(self) -> Dict[str, Any]:
        return {"thirdPartyId": self.third_party_id, "name": self.name}


class TenantInfo:
    def __init__(
        self,
        tenant_id: str,
        third_party: List[ThirdPartyProvider],
        first_factors: List[str],
        required_secondary_factors: Optional[List[str]],
        core_config: List[CoreConfigFieldInfo],
        user_count: int,
    ):
        self.tenant_id = tenant_id
        self.third_party = third_party
        self.first_factors = first_factors
        self.required_secondary_factors = required_secondary_factors
        self.core_config = core_config
        self.user_count = user_count

    def to_json(self) -> Dict[str, Any]:
        return {
            "tenantId": self.tenant_id,
            "thirdParty": {
                "providers": [provider.to_json() for provider in self.third_party]
            },
            "firstFactors": self.first_factors,
            "requiredSecondaryFactors": self.required_secondary_factors,
            "coreConfig": [field.to_json() for field in self.core_config],
            "userCount": self.user_count,
        }


class GetTenantInfoOkResult(APIResponse):
    def __init__(self, tenant: TenantInfo):
        self.status: Literal["OK"] = "OK"
        self.tenant = tenant

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "tenant": self.tenant.to_json()}


class GetTenantInfoUnknownTenantError(APIResponse):
    def __init__(self):
        self.status: Literal["UNKNOWN_TENANT_ERROR"] = "UNKNOWN_TENANT_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


async def get_tenant_info(
    _: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[GetTenantInfoOkResult, GetTenantInfoUnknownTenantError]:
    tenant_res = await get_tenant(tenant_id, user_context)

    if tenant_res is None:
        return GetTenantInfoUnknownTenantError()

    first_factors = (
        get_normalised_first_factors_based_on_tenant_config_from_core_and_sdk_init(
            tenant_res
        )
    )

    user_count = await Supertokens.get_instance().get_user_count(
        None, tenant_id, user_context
    )

    providers_from_core = tenant_res.third_party_providers
    mt_recipe = MultitenancyRecipe.get_instance()
    static_providers = mt_recipe.static_third_party_providers

    merged_providers_from_core_and_static = merge_providers_from_core_and_static(
        providers_from_core, static_providers, tenant_id == DEFAULT_TENANT_ID
    )

    querier = Querier.get_instance(options.recipe_id)
    core_config = await querier.send_get_request(
        NormalisedURLPath(f"/{tenant_id}/recipe/dashboard/tenant/core-config"),
        {},
        user_context,
    )

    providers: List[ThirdPartyProvider] = []
    for provider in merged_providers_from_core_and_static:
        try:
            provider_instance = await find_and_create_provider_instance(
                merged_providers_from_core_and_static,
                provider.config.third_party_id,
                (
                    provider.config.clients[0].client_type
                    if provider.config.clients
                    else None
                ),
                user_context,
            )
            assert provider_instance is not None
            if provider_instance.config.name is None:
                raise Exception("Falling back to exception block")
            providers.append(
                ThirdPartyProvider(
                    provider.config.third_party_id,
                    provider_instance.config.name,
                ),
            )
        except Exception:
            providers.append(
                ThirdPartyProvider(
                    provider.config.third_party_id, provider.config.third_party_id
                )
            )

    tenant = TenantInfo(
        tenant_id,
        providers,
        first_factors,
        tenant_res.required_secondary_factors,
        [CoreConfigFieldInfo.from_json(field) for field in core_config["config"]],
        user_count,
    )

    return GetTenantInfoOkResult(tenant)
