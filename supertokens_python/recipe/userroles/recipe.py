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

from os import environ
from typing import Any, Dict, List, Optional, Set, Union

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.session.asyncio import get_session_information
from supertokens_python.recipe.userroles.recipe_implementation import (
    RecipeImplementation,
)
from supertokens_python.recipe.userroles.utils import validate_and_normalise_user_input
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.supertokens import AppInfo
from supertokens_python.types import RecipeUserId, User

from ...post_init_callbacks import PostSTInitCallbacks
from ..session import SessionRecipe
from ..session.claim_base_classes.primitive_array_claim import PrimitiveArrayClaim
from .exceptions import SuperTokensUserRolesError
from .interfaces import GetPermissionsForRoleOkResult, UnknownRoleError
from .utils import InputOverrideConfig


class UserRolesRecipe(RecipeModule):
    recipe_id = "userroles"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        skip_adding_roles_to_access_token: Optional[bool] = None,
        skip_adding_permissions_to_access_token: Optional[bool] = None,
        override: Union[InputOverrideConfig, None] = None,
    ):
        from ..oauth2provider.recipe import OAuth2ProviderRecipe

        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            self,
            app_info,
            skip_adding_roles_to_access_token,
            skip_adding_permissions_to_access_token,
            override,
        )
        recipe_implementation = RecipeImplementation(Querier.get_instance(recipe_id))
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        def callback():
            if self.config.skip_adding_roles_to_access_token is False:
                SessionRecipe.get_instance().add_claim_from_other_recipe(UserRoleClaim)
            if self.config.skip_adding_permissions_to_access_token is False:
                SessionRecipe.get_instance().add_claim_from_other_recipe(
                    PermissionClaim
                )

            async def token_payload_builder(
                user: User,
                scopes: List[str],
                session_handle: str,
                user_context: Dict[str, Any],
            ) -> Dict[str, Any]:
                payload: Dict[str, Any] = {"roles": None, "permissions": None}

                session_info = await get_session_information(
                    session_handle, user_context
                )

                if session_info is None:
                    raise Exception("should never come here")

                user_roles: List[str] = []

                if "roles" in scopes or "permissions" in scopes:
                    res = await self.recipe_implementation.get_roles_for_user(
                        tenant_id=session_info.tenant_id,
                        user_id=user.id,
                        user_context=user_context,
                    )

                    user_roles = res.roles

                if "roles" in scopes:
                    payload["roles"] = user_roles

                if "permissions" in scopes:
                    user_permissions: Set[str] = set()
                    for role in user_roles:
                        role_permissions = (
                            await self.recipe_implementation.get_permissions_for_role(
                                role=role,
                                user_context=user_context,
                            )
                        )

                        if isinstance(role_permissions, UnknownRoleError):
                            raise Exception("Failed to fetch permissions for the role")

                        for perm in role_permissions.permissions:
                            user_permissions.add(perm)

                    payload["permissions"] = list(user_permissions)

                return payload

            OAuth2ProviderRecipe.get_instance().add_access_token_builder_from_other_recipe(
                token_payload_builder
            )
            OAuth2ProviderRecipe.get_instance().add_id_token_builder_from_other_recipe(
                token_payload_builder
            )

            async def user_info_builder(
                user: User,
                _access_token_payload: Dict[str, Any],
                scopes: List[str],
                tenant_id: str,
                user_context: Dict[str, Any],
            ) -> Dict[str, Any]:
                user_info: Dict[str, Any] = {"roles": None, "permissions": None}

                user_roles = []

                if "roles" in scopes or "permissions" in scopes:
                    res = await self.recipe_implementation.get_roles_for_user(
                        tenant_id=tenant_id,
                        user_id=user.id,
                        user_context=user_context,
                    )

                    user_roles = res.roles

                if "roles" in scopes:
                    user_info["roles"] = user_roles

                if "permissions" in scopes:
                    user_permissions: Set[str] = set()
                    for role in user_roles:
                        role_permissions = (
                            await self.recipe_implementation.get_permissions_for_role(
                                role=role,
                                user_context=user_context,
                            )
                        )

                        if isinstance(role_permissions, UnknownRoleError):
                            raise Exception("Failed to fetch permissions for the role")

                        for perm in role_permissions.permissions:
                            user_permissions.add(perm)

                    user_info["permissions"] = list(user_permissions)

                return user_info

            OAuth2ProviderRecipe.get_instance().add_user_info_builder_from_other_recipe(
                user_info_builder
            )

        PostSTInitCallbacks.add_post_init_callback(callback)

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensUserRolesError)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        return []

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: Optional[str],
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Union[BaseResponse, None]:
        raise Exception("Should never come here")

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(
        skip_adding_roles_to_access_token: Optional[bool] = None,
        skip_adding_permissions_to_access_token: Optional[bool] = None,
        override: Union[InputOverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if UserRolesRecipe.__instance is None:
                UserRolesRecipe.__instance = UserRolesRecipe(
                    UserRolesRecipe.recipe_id,
                    app_info,
                    skip_adding_roles_to_access_token,
                    skip_adding_permissions_to_access_token,
                    override,
                )
                return UserRolesRecipe.__instance
            raise Exception(
                None,
                "UserRoles recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        UserRolesRecipe.__instance = None

    @staticmethod
    def get_instance() -> UserRolesRecipe:
        if UserRolesRecipe.__instance is not None:
            return UserRolesRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init or UserRoles.init function?"
        )


class PermissionClaimClass(PrimitiveArrayClaim[List[str]]):
    def __init__(self) -> None:
        key = "st-perm"
        default_max_age_in_sec = 300

        async def fetch_value(
            user_id: str,
            _recipe_user_id: RecipeUserId,
            tenant_id: str,
            _current_payload: Dict[str, Any],
            user_context: Dict[str, Any],
        ) -> List[str]:
            recipe = UserRolesRecipe.get_instance()

            user_roles = await recipe.recipe_implementation.get_roles_for_user(
                user_id, tenant_id, user_context
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

        super().__init__(key, fetch_value, default_max_age_in_sec)


PermissionClaim = PermissionClaimClass()


class UserRoleClaimClass(PrimitiveArrayClaim[List[str]]):
    def __init__(self) -> None:
        key = "st-role"
        default_max_age_in_sec = 300

        async def fetch_value(
            user_id: str,
            _recipe_user_id: RecipeUserId,
            tenant_id: str,
            _current_payload: Dict[str, Any],
            user_context: Dict[str, Any],
        ) -> List[str]:
            recipe = UserRolesRecipe.get_instance()
            res = await recipe.recipe_implementation.get_roles_for_user(
                user_id, tenant_id, user_context
            )
            return res.roles

        super().__init__(key, fetch_value, default_max_age_in_sec)


UserRoleClaim = UserRoleClaimClass()
