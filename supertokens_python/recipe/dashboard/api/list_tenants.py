# Copyright (c) 2023, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import TYPE_CHECKING, Any, Dict, List

from supertokens_python.recipe.dashboard.interfaces import DashboardListTenantItem

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )
    from supertokens_python.types import APIResponse

from supertokens_python.recipe.multitenancy.asyncio import list_all_tenants
from supertokens_python.recipe.dashboard.interfaces import (
    DashboardListTenantsGetResponse,
)


async def handle_list_tenants_api(
    _api_implementation: APIInterface,
    _tenant_id: str,
    _api_options: APIOptions,
    user_context: Dict[str, Any],
) -> APIResponse:
    tenants = await list_all_tenants(user_context)

    final_tenants: List[DashboardListTenantItem] = []

    for current_tenant in tenants.tenants:
        dashboard_tenant = DashboardListTenantItem(
            tenant_id=current_tenant.tenant_id,
            emailpassword=current_tenant.emailpassword,
            passwordless=current_tenant.passwordless,
            third_party=current_tenant.third_party,
        )
        final_tenants.append(dashboard_tenant)

    return DashboardListTenantsGetResponse(final_tenants)
