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
from typing import Any, Dict, Optional, TYPE_CHECKING

from supertokens_python.async_to_sync_wrapper import sync

if TYPE_CHECKING:
    from ..interfaces import TenantConfig, ProviderConfig


def create_or_update_tenant(
    tenant_id: str,
    config: Optional[TenantConfig],
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import create_or_update_tenant

    return sync(create_or_update_tenant(tenant_id, config, user_context))


def delete_tenant(tenant_id: str, user_context: Optional[Dict[str, Any]] = None):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import delete_tenant

    return sync(delete_tenant(tenant_id, user_context))


def get_tenant(tenant_id: str, user_context: Optional[Dict[str, Any]] = None):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import get_tenant

    return sync(get_tenant(tenant_id, user_context))


def list_all_tenants(user_context: Optional[Dict[str, Any]] = None):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import list_all_tenants

    return sync(list_all_tenants(user_context))


def create_or_update_third_party_config(
    tenant_id: str,
    config: ProviderConfig,
    skip_validation: Optional[bool] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import (
        create_or_update_third_party_config,
    )

    return sync(
        create_or_update_third_party_config(
            tenant_id, config, skip_validation, user_context
        )
    )


def delete_third_party_config(
    tenant_id: str,
    third_party_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import delete_third_party_config

    return sync(delete_third_party_config(tenant_id, third_party_id, user_context))


def associate_user_to_tenant(
    tenant_id: str,
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import associate_user_to_tenant

    return sync(associate_user_to_tenant(tenant_id, user_id, user_context))


def dissociate_user_from_tenant(
    tenant_id: str,
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multitenancy.asyncio import (
        dissociate_user_from_tenant,
    )

    return sync(dissociate_user_from_tenant(tenant_id, user_id, user_context))
