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
from typing import List, Any, Set, Dict

from supertokens_python.recipe.session.claim_base_classes.primitive_array_claim import (
    PrimitiveArrayClaim,
)
from supertokens_python.recipe.userroles import UserRolesRecipe
from supertokens_python.recipe.userroles.interfaces import GetPermissionsForRoleOkResult


class PermissionClaimClass(PrimitiveArrayClaim[List[str]]):
    def __init__(self) -> None:
        key = "st-perm"

        async def fetch_value(user_id: str, user_context: Dict[str, Any]) -> List[str]:
            recipe = UserRolesRecipe.get_instance()

            user_roles = await recipe.recipe_implementation.get_roles_for_user(
                user_id, user_context
            )

            user_permissions: Set[str] = set()

            for role in user_roles.roles:
                role_permissions = (
                    await recipe.recipe_implementation.get_permissions_for_role(
                        role, user_context
                    )
                )

                if isinstance(role_permissions, GetPermissionsForRoleOkResult):
                    for permission in role_permissions.permissions:
                        user_permissions.add(permission)

            return list(user_permissions)

        super().__init__(key, fetch_value)


PermissionClaim = PermissionClaimClass()
