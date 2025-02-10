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

from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from supertokens_python.types import RecipeUserId

from ..interfaces import (
    AssociateUserToTenantEmailAlreadyExistsError,
    AssociateUserToTenantNotAllowedError,
    AssociateUserToTenantOkResult,
    AssociateUserToTenantPhoneNumberAlreadyExistsError,
    AssociateUserToTenantThirdPartyUserAlreadyExistsError,
    AssociateUserToTenantUnknownUserIdError,
    CreateOrUpdateTenantOkResult,
    CreateOrUpdateThirdPartyConfigOkResult,
    DeleteTenantOkResult,
    DeleteThirdPartyConfigOkResult,
    DisassociateUserFromTenantOkResult,
    ListAllTenantsOkResult,
    TenantConfig,
    TenantConfigCreateOrUpdate,
)

if TYPE_CHECKING:
    from ..interfaces import ProviderConfig


async def create_or_update_tenant(
    tenant_id: str,
    config: Optional[TenantConfigCreateOrUpdate],
    user_context: Optional[Dict[str, Any]] = None,
) -> CreateOrUpdateTenantOkResult:
    if user_context is None:
        user_context = {}
    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.create_or_update_tenant(
        tenant_id, config, user_context
    )


async def delete_tenant(
    tenant_id: str, user_context: Optional[Dict[str, Any]] = None
) -> DeleteTenantOkResult:
    if user_context is None:
        user_context = {}
    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.delete_tenant(tenant_id, user_context)


async def get_tenant(
    tenant_id: str, user_context: Optional[Dict[str, Any]] = None
) -> Optional[TenantConfig]:
    if user_context is None:
        user_context = {}
    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.get_tenant(tenant_id, user_context)


async def list_all_tenants(
    user_context: Optional[Dict[str, Any]] = None,
) -> ListAllTenantsOkResult:
    if user_context is None:
        user_context = {}

    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.list_all_tenants(user_context)


async def create_or_update_third_party_config(
    tenant_id: str,
    config: ProviderConfig,
    skip_validation: Optional[bool] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> CreateOrUpdateThirdPartyConfigOkResult:
    if user_context is None:
        user_context = {}

    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.create_or_update_third_party_config(
        tenant_id, config, skip_validation, user_context
    )


async def delete_third_party_config(
    tenant_id: str,
    third_party_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> DeleteThirdPartyConfigOkResult:
    if user_context is None:
        user_context = {}

    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.delete_third_party_config(
        tenant_id, third_party_id, user_context
    )


async def associate_user_to_tenant(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    AssociateUserToTenantOkResult,
    AssociateUserToTenantUnknownUserIdError,
    AssociateUserToTenantEmailAlreadyExistsError,
    AssociateUserToTenantPhoneNumberAlreadyExistsError,
    AssociateUserToTenantThirdPartyUserAlreadyExistsError,
    AssociateUserToTenantNotAllowedError,
]:
    if user_context is None:
        user_context = {}

    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.associate_user_to_tenant(
        tenant_id, recipe_user_id, user_context
    )


async def disassociate_user_from_tenant(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    user_context: Optional[Dict[str, Any]] = None,
) -> DisassociateUserFromTenantOkResult:
    if user_context is None:
        user_context = {}

    from ..recipe import MultitenancyRecipe

    recipe = MultitenancyRecipe.get_instance()

    return await recipe.recipe_implementation.disassociate_user_from_tenant(
        tenant_id, recipe_user_id, user_context
    )
