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

from typing import Any, Dict, List, Union

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.userroles.interfaces import (
    AddRoleToUserOkResult,
    CreateNewRoleOrAddPermissionsOkResult,
    DeleteRoleOkResult,
    GetAllRolesOkResult,
    GetPermissionsForRoleOkResult,
    GetRolesForUserOkResult,
    GetRolesThatHavePermissionOkResult,
    GetUsersThatHaveRoleOkResult,
    RemovePermissionsFromRoleOkResult,
    RemoveUserRoleOkResult,
    UnknownRoleError,
)


def add_role_to_user(
    tenant_id: str,
    user_id: str,
    role: str,
    user_context: Union[Dict[str, Any], None] = None,
) -> Union[AddRoleToUserOkResult, UnknownRoleError]:
    from supertokens_python.recipe.userroles.asyncio import add_role_to_user

    return sync(add_role_to_user(tenant_id, user_id, role, user_context))


def remove_user_role(
    tenant_id: str,
    user_id: str,
    role: str,
    user_context: Union[Dict[str, Any], None] = None,
) -> Union[RemoveUserRoleOkResult, UnknownRoleError]:
    from supertokens_python.recipe.userroles.asyncio import remove_user_role

    return sync(remove_user_role(tenant_id, user_id, role, user_context))


def get_roles_for_user(
    tenant_id: str, user_id: str, user_context: Union[Dict[str, Any], None] = None
) -> GetRolesForUserOkResult:
    from supertokens_python.recipe.userroles.asyncio import get_roles_for_user

    return sync(get_roles_for_user(tenant_id, user_id, user_context))


def get_users_that_have_role(
    tenant_id: str, role: str, user_context: Union[Dict[str, Any], None] = None
) -> Union[GetUsersThatHaveRoleOkResult, UnknownRoleError]:
    from supertokens_python.recipe.userroles.asyncio import get_users_that_have_role

    return sync(get_users_that_have_role(tenant_id, role, user_context))


def create_new_role_or_add_permissions(
    role: str, permissions: List[str], user_context: Union[Dict[str, Any], None] = None
) -> CreateNewRoleOrAddPermissionsOkResult:
    from supertokens_python.recipe.userroles.asyncio import (
        create_new_role_or_add_permissions,
    )

    return sync(create_new_role_or_add_permissions(role, permissions, user_context))


def get_permissions_for_role(
    role: str, user_context: Union[Dict[str, Any], None] = None
) -> Union[GetPermissionsForRoleOkResult, UnknownRoleError]:
    from supertokens_python.recipe.userroles.asyncio import get_permissions_for_role

    return sync(get_permissions_for_role(role, user_context))


def remove_permissions_from_role(
    role: str, permissions: List[str], user_context: Union[Dict[str, Any], None] = None
) -> Union[RemovePermissionsFromRoleOkResult, UnknownRoleError]:
    from supertokens_python.recipe.userroles.asyncio import remove_permissions_from_role

    return sync(remove_permissions_from_role(role, permissions, user_context))


def get_roles_that_have_permission(
    permission: str, user_context: Union[Dict[str, Any], None] = None
) -> GetRolesThatHavePermissionOkResult:
    from supertokens_python.recipe.userroles.asyncio import (
        get_roles_that_have_permission,
    )

    return sync(get_roles_that_have_permission(permission, user_context))


def delete_role(
    role: str, user_context: Union[Dict[str, Any], None] = None
) -> DeleteRoleOkResult:
    from supertokens_python.recipe.userroles.asyncio import delete_role

    return sync(delete_role(role, user_context))


def get_all_roles(
    user_context: Union[Dict[str, Any], None] = None
) -> GetAllRolesOkResult:
    from supertokens_python.recipe.userroles.asyncio import get_all_roles

    return sync(get_all_roles(user_context))
