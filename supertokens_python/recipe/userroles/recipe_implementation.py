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

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

from .interfaces import (
    AddRoleToUserOkResult,
    CreateNewRoleOrAddPermissionsOkResult,
    DeleteRoleOkResult,
    GetAllRolesOkResult,
    GetPermissionsForRoleOkResult,
    GetRolesForUserOkResult,
    GetRolesThatHavePermissionOkResult,
    GetUsersThatHaveRoleOkResult,
    RecipeInterface,
    RemovePermissionsFromRoleOkResult,
    RemoveUserRoleOkResult,
    UnknownRoleError,
)


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def add_role_to_user(
        self, user_id: str, role: str, user_context: Dict[str, Any]
    ) -> Union[AddRoleToUserOkResult, UnknownRoleError]:
        params = {"userId": user_id, "role": role}
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user/role"), params
        )
        if response.get("status") == "OK":
            return AddRoleToUserOkResult(
                did_user_already_have_role=response["didUserAlreadyHaveRole"]
            )
        return UnknownRoleError()

    async def remove_user_role(
        self, user_id: str, role: str, user_context: Dict[str, Any]
    ) -> Union[RemoveUserRoleOkResult, UnknownRoleError]:
        params = {"userId": user_id, "role": role}
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/user/role/remove"), params
        )
        if response["status"] == "OK":
            return RemoveUserRoleOkResult(
                did_user_have_role=response["didUserHaveRole"]
            )
        return UnknownRoleError()

    async def get_roles_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> GetRolesForUserOkResult:
        params = {"userId": user_id}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user/roles"), params
        )
        return GetRolesForUserOkResult(roles=response["roles"])

    async def get_users_that_have_role(
        self, role: str, user_context: Dict[str, Any]
    ) -> Union[GetUsersThatHaveRoleOkResult, UnknownRoleError]:
        params = {"role": role}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/role/users"), params
        )
        if response.get("status") == "OK":
            return GetUsersThatHaveRoleOkResult(users=response["users"])
        return UnknownRoleError()

    async def create_new_role_or_add_permissions(
        self, role: str, permissions: List[str], user_context: Dict[str, Any]
    ) -> CreateNewRoleOrAddPermissionsOkResult:
        params = {"role": role, "permissions": permissions}
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/role"), params
        )
        return CreateNewRoleOrAddPermissionsOkResult(
            created_new_role=response["createdNewRole"]
        )

    async def get_permissions_for_role(
        self, role: str, user_context: Dict[str, Any]
    ) -> Union[GetPermissionsForRoleOkResult, UnknownRoleError]:
        params = {"role": role}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/role/permissions"), params
        )
        if response.get("status") == "OK":
            return GetPermissionsForRoleOkResult(permissions=response["permissions"])
        return UnknownRoleError()

    async def remove_permissions_from_role(
        self, role: str, permissions: List[str], user_context: Dict[str, Any]
    ) -> Union[RemovePermissionsFromRoleOkResult, UnknownRoleError]:
        params = {"role": role, "permissions": permissions}
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/role/permissions/remove"), params
        )
        if response.get("status") == "OK":
            return RemovePermissionsFromRoleOkResult()
        return UnknownRoleError()

    async def get_roles_that_have_permission(
        self, permission: str, user_context: Dict[str, Any]
    ) -> GetRolesThatHavePermissionOkResult:
        params = {"permission": permission}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/permission/roles"), params
        )
        return GetRolesThatHavePermissionOkResult(roles=response["roles"])

    async def delete_role(
        self, role: str, user_context: Dict[str, Any]
    ) -> DeleteRoleOkResult:
        params = {"role": role}
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/role/remove"), params
        )
        return DeleteRoleOkResult(did_role_exist=response["didRoleExist"])

    async def get_all_roles(self, user_context: Dict[str, Any]) -> GetAllRolesOkResult:
        params = {}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/roles"), params
        )
        return GetAllRolesOkResult(roles=response["roles"])
