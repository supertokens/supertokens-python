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

import asyncio
from typing import Any, Dict, Union

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    create_or_update_third_party_config,
    delete_third_party_config,
    get_tenant,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfigCreateOrUpdate
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.thirdparty import ProviderConfig
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions


class DeleteThirdPartyConfigOkResult(APIResponse):
    def __init__(self, did_config_exist: bool):
        self.status: Literal["OK"] = "OK"
        self.did_config_exist = did_config_exist

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "didConfigExist": self.did_config_exist}


class DeleteThirdPartyConfigUnknownTenantError(APIResponse):
    def __init__(self):
        self.status: Literal["UNKNOWN_TENANT_ERROR"] = "UNKNOWN_TENANT_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


async def delete_third_party_config_api(
    _: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[DeleteThirdPartyConfigOkResult, DeleteThirdPartyConfigUnknownTenantError]:
    third_party_id = options.request.get_query_param("thirdPartyId")

    if not tenant_id or not third_party_id:
        raise_bad_input_exception(
            "Missing required parameter 'tenantId' or 'thirdPartyId'"
        )

    assert third_party_id is not None

    tenant_res = await get_tenant(tenant_id, user_context)
    if tenant_res is None:
        return DeleteThirdPartyConfigUnknownTenantError()

    third_party_ids_from_core = [
        provider.third_party_id for provider in tenant_res.third_party_providers
    ]

    if len(third_party_ids_from_core) == 0:
        # This means that the tenant was using the static list of providers, we need to add them all before deleting one
        mt_recipe = MultitenancyRecipe.get_instance()
        static_providers = (
            mt_recipe.static_third_party_providers if mt_recipe.config else []
        )
        static_provider_ids = [
            provider.config.third_party_id for provider in static_providers
        ]

        for provider_id in static_provider_ids:
            await create_or_update_third_party_config(
                tenant_id,
                ProviderConfig(third_party_id=provider_id),
                None,
                user_context,
            )
            # Delay after each provider to avoid rate limiting
            await asyncio.sleep(0.5)  # 500ms
    elif (
        len(third_party_ids_from_core) == 1
        and third_party_ids_from_core[0] == third_party_id
    ):
        if tenant_res.first_factors is None:
            # Add all static first factors except thirdparty
            await create_or_update_tenant(
                tenant_id,
                TenantConfigCreateOrUpdate(
                    first_factors=[
                        FactorIds.EMAILPASSWORD,
                        FactorIds.OTP_PHONE,
                        FactorIds.OTP_EMAIL,
                        FactorIds.LINK_PHONE,
                        FactorIds.LINK_EMAIL,
                    ]
                ),
                user_context,
            )
        elif "thirdparty" in tenant_res.first_factors:
            # Add all static first factors except thirdparty
            new_first_factors = [
                factor for factor in tenant_res.first_factors if factor != "thirdparty"
            ]
            await create_or_update_tenant(
                tenant_id,
                TenantConfigCreateOrUpdate(first_factors=new_first_factors),
                user_context,
            )

    result = await delete_third_party_config(tenant_id, third_party_id, user_context)
    return DeleteThirdPartyConfigOkResult(result.did_config_exist)
