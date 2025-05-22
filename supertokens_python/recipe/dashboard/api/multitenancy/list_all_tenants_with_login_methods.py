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

from typing import Any, Dict, List

from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions
from .utils import (
    get_normalised_first_factors_based_on_tenant_config_from_core_and_sdk_init,
)


class TenantWithLoginMethods:
    def __init__(self, tenant_id: str, first_factors: List[str]):
        self.tenant_id = tenant_id
        self.first_factors = first_factors


class ListAllTenantsWithLoginMethodsOkResult(APIResponse):
    def __init__(self, tenants: List[TenantWithLoginMethods]):
        self.status = "OK"
        self.tenants = tenants

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "tenants": [
                {"tenantId": tenant.tenant_id, "firstFactors": tenant.first_factors}
                for tenant in self.tenants
            ],
        }


async def list_all_tenants_with_login_methods(
    _: APIInterface,
    __: str,
    ___: APIOptions,
    user_context: Dict[str, Any],
) -> ListAllTenantsWithLoginMethodsOkResult:
    tenants_res = (
        await MultitenancyRecipe.get_instance().recipe_implementation.list_all_tenants(
            user_context
        )
    )
    final_tenants: List[TenantWithLoginMethods] = []

    for current_tenant in tenants_res.tenants:
        login_methods = (
            get_normalised_first_factors_based_on_tenant_config_from_core_and_sdk_init(
                current_tenant
            )
        )

        final_tenants.append(
            TenantWithLoginMethods(
                tenant_id=current_tenant.tenant_id,
                first_factors=login_methods,
            )
        )

    return ListAllTenantsWithLoginMethodsOkResult(tenants=final_tenants)
