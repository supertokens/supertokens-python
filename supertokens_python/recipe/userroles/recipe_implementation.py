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


from typing import Any, Dict, List

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

from .interfaces import (AddRoleToUserOkResult, AddRoleToUserResult,
                         CreateNewRoleOrAddPermissionsResult, DeleteRoleResult,
                         GetAllRolesResult, GetPermissionsForRoleOkResult,
                         GetPermissionsForRoleResult, GetRolesForUserResult,
                         GetRolesThatHavePermissionResult,
                         GetUsersThatHaveRoleOkResult,
                         GetUsersThatHaveRoleResult, RecipeInterface,
                         RemovePermissionsFromRoleOkResult,
                         RemovePermissionsFromRoleResult,
                         RemoveUserRoleOkResult, RemoveUserRoleResult,
                         UnknownRoleError)


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def add_role_to_user(self, user_id: str, role: str, user_context: Dict[str, Any]) -> AddRoleToUserResult:
        params = {"userId": user_id, "role": role}
        response = await self.querier.send_put_request(NormalisedURLPath("/recipe/user/role"), params)
        if response.get("status") == "OK":
            return AddRoleToUserOkResult(did_user_already_have_role=response["didUserAlreadyHaveRole"])
        return UnknownRoleError()

    async def remove_user_role(self, user_id: str, role: str, user_context: Dict[str, Any]) -> RemoveUserRoleResult:
        params = {"userId": user_id, "role": role}
        response = await self.querier.send_post_request(NormalisedURLPath("/recipe/user/role/remove"), params)
        if response["status"] == "OK":
            return RemoveUserRoleOkResult(did_user_have_role=response["didUserHaveRole"])
        return UnknownRoleError()

    async def get_roles_for_user(self, user_id: str, user_context: Dict[str, Any]) -> GetRolesForUserResult:
        params = {"userId": user_id}
        response = await self.querier.send_get_request(NormalisedURLPath("/recipe/user/roles"), params)
        return GetRolesForUserResult(roles=response["roles"])

    async def get_users_that_have_role(self, role: str, user_context: Dict[str, Any]) -> GetUsersThatHaveRoleResult:
        params = {"role": role}
        response = await self.querier.send_get_request(NormalisedURLPath("/recipe/role/users"), params)
        if response.get("status") == "OK":
            return GetUsersThatHaveRoleOkResult(users=response["users"])
        return UnknownRoleError()

    async def create_new_role_or_add_permissions(self, role: str, permissions: List[str],
                                                 user_context: Dict[str, Any]) -> CreateNewRoleOrAddPermissionsResult:
        params = {"role": role, "permissions": permissions}
        response = await self.querier.send_put_request(NormalisedURLPath("/recipe/role"), params)
        return CreateNewRoleOrAddPermissionsResult(created_new_role=response["createdNewRole"])

    async def get_permissions_for_role(self, role: str, user_context: Dict[str, Any]) -> GetPermissionsForRoleResult:
        params = {"role": role}
        response = await self.querier.send_get_request(NormalisedURLPath("/recipe/role/permissions"), params)
        if response.get("status") == "OK":
            return GetPermissionsForRoleOkResult(permissions=response["permissions"])
        return UnknownRoleError()

    async def remove_permissions_from_role(self, role: str, permissions: List[str],
                                           user_context: Dict[str, Any]) -> RemovePermissionsFromRoleResult:
        params = {"role": role, "permissions": permissions}
        response = await self.querier.send_post_request(NormalisedURLPath("/recipe/role/permissions/remove"), params)
        if response.get("status") == "OK":
            return RemovePermissionsFromRoleOkResult()
        return UnknownRoleError()

    async def get_roles_that_have_permission(self, permission: str,
                                             user_context: Dict[str, Any]) -> GetRolesThatHavePermissionResult:
        params = {"permissions": permission}
        response = await self.querier.send_get_request(NormalisedURLPath("/recipe/permission/roles"), params)
        return GetRolesThatHavePermissionResult(roles=response["roles"])

    async def delete_role(self, role: str, user_context: Dict[str, Any]) -> DeleteRoleResult:
        params = {"role": role}
        response = await self.querier.send_post_request(NormalisedURLPath("/recipe/role/remove"), params)
        return DeleteRoleResult(did_role_exist=response["didRoleExist"])

    async def get_all_roles(self, user_context: Dict[str, Any]) -> GetAllRolesResult:
        params = {}
        response = await self.querier.send_get_request(NormalisedURLPath("/recipe/roles"), params)
        return GetAllRolesResult(roles=response["roles"])
