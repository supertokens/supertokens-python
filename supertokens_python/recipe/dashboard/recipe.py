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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.dashboard.api.multitenancy.create_or_update_third_party_config import (
    handle_create_or_update_third_party_config,
)
from supertokens_python.recipe.dashboard.api.multitenancy.create_tenant import (
    create_tenant,
)
from supertokens_python.recipe.dashboard.api.multitenancy.delete_tenant import (
    delete_tenant_api,
)
from supertokens_python.recipe.dashboard.api.multitenancy.delete_third_party_config import (
    delete_third_party_config_api,
)
from supertokens_python.recipe.dashboard.api.multitenancy.get_tenant_info import (
    get_tenant_info,
)
from supertokens_python.recipe.dashboard.api.multitenancy.get_third_party_config import (
    get_third_party_config,
)
from supertokens_python.recipe.dashboard.api.multitenancy.list_all_tenants_with_login_methods import (
    list_all_tenants_with_login_methods,
)
from supertokens_python.recipe.dashboard.api.multitenancy.update_tenant_core_config import (
    update_tenant_core_config,
)
from supertokens_python.recipe.dashboard.api.multitenancy.update_tenant_first_factor import (
    update_tenant_first_factor,
)
from supertokens_python.recipe.dashboard.api.multitenancy.update_tenant_secondary_factor import (
    update_tenant_secondary_factor,
)
from supertokens_python.recipe.dashboard.api.user.create.emailpassword_user import (
    create_email_password_user,
)
from supertokens_python.recipe.dashboard.api.user.create.passwordless_user import (
    create_passwordless_user,
)
from supertokens_python.recipe.dashboard.api.userdetails.user_unlink_get import (
    handle_user_unlink_get,
)
from supertokens_python.recipe.dashboard.api.userroles.add_role_to_user import (
    add_role_to_user_api,
)
from supertokens_python.recipe.dashboard.api.userroles.get_role_to_user import (
    get_roles_for_user_api,
)
from supertokens_python.recipe.dashboard.api.userroles.permissions.get_permissions_for_role import (
    get_permissions_for_role_api,
)
from supertokens_python.recipe.dashboard.api.userroles.permissions.remove_permissions_from_role import (
    remove_permissions_from_role_api,
)
from supertokens_python.recipe.dashboard.api.userroles.remove_user_role import (
    remove_user_role_api,
)
from supertokens_python.recipe.dashboard.api.userroles.roles.create_role_or_add_permissions import (
    create_role_or_add_permissions_api,
)
from supertokens_python.recipe.dashboard.api.userroles.roles.delete_role import (
    delete_role_api,
)
from supertokens_python.recipe.dashboard.api.userroles.roles.get_all_roles import (
    get_all_roles_api,
)
from supertokens_python.recipe_module import APIHandled, RecipeModule

from .api import (
    api_key_protector,
    handle_analytics_post,
    handle_dashboard_api,
    handle_email_verify_token_post,
    handle_emailpassword_signin_api,
    handle_emailpassword_signout_api,
    handle_get_tags,
    handle_metadata_get,
    handle_metadata_put,
    handle_sessions_get,
    handle_user_delete,
    handle_user_email_verify_get,
    handle_user_email_verify_put,
    handle_user_get,
    handle_user_password_put,
    handle_user_put,
    handle_user_sessions_post,
    handle_users_count_get_api,
    handle_users_get_api,
    handle_validate_key_api,
)
from .api.implementation import APIImplementation
from .exceptions import SuperTokensDashboardError
from .interfaces import APIInterface, APIOptions
from .recipe_implementation import RecipeImplementation

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.types.response import APIResponse

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.recipe.dashboard.utils import get_api_path_with_dashboard_base

from .constants import (
    CREATE_EMAIL_PASSWORD_USER,
    CREATE_PASSWORDLESS_USER,
    DASHBOARD_ANALYTICS_API,
    DASHBOARD_API,
    LIST_TENANTS_WITH_LOGIN_METHODS,
    SEARCH_TAGS_API,
    SIGN_IN_API,
    SIGN_OUT_API,
    TENANT_API,
    TENANT_THIRD_PARTY_CONFIG_API,
    UNLINK_USER,
    UPDATE_TENANT_CORE_CONFIG_API,
    UPDATE_TENANT_FIRST_FACTOR_API,
    UPDATE_TENANT_REQUIRED_SECONDARY_FACTOR_API,
    USER_API,
    USER_EMAIL_VERIFY_API,
    USER_EMAIL_VERIFY_TOKEN_API,
    USER_METADATA_API,
    USER_PASSWORD_API,
    USER_SESSION_API,
    USERROLES_LIST_API,
    USERROLES_PERMISSIONS_API,
    USERROLES_REMOVE_PERMISSIONS_API,
    USERROLES_ROLE_API,
    USERROLES_USER_API,
    USERS_COUNT_API,
    USERS_LIST_GET_API,
    VALIDATE_KEY_API,
)
from .utils import (
    InputOverrideConfig,
    validate_and_normalise_user_input,
)


class DashboardRecipe(RecipeModule):
    recipe_id = "dashboard"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        api_key: Optional[str],
        admins: Optional[List[str]],
        override: Optional[InputOverrideConfig] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            api_key,
            admins,
            override,
        )
        recipe_implementation = RecipeImplementation()
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        api_implementation = APIImplementation()
        self.api_implementation = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensDashboardError)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base("/")),
                "get",
                DASHBOARD_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base("/roles")),
                "get",
                DASHBOARD_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base("/tenants")),
                "get",
                DASHBOARD_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(SIGN_IN_API)),
                "post",
                SIGN_IN_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(VALIDATE_KEY_API)),
                "post",
                VALIDATE_KEY_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(SIGN_OUT_API)),
                "post",
                SIGN_OUT_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERS_LIST_GET_API)),
                "get",
                USERS_LIST_GET_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERS_COUNT_API)),
                "get",
                USERS_COUNT_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_API)),
                "get",
                USER_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_API)),
                "post",
                USER_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_API)),
                "put",
                USER_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_API)),
                "delete",
                USER_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(USER_EMAIL_VERIFY_API)
                ),
                "get",
                USER_EMAIL_VERIFY_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(USER_EMAIL_VERIFY_API)
                ),
                "put",
                USER_EMAIL_VERIFY_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_METADATA_API)),
                "get",
                USER_METADATA_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_METADATA_API)),
                "put",
                USER_METADATA_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_SESSION_API)),
                "get",
                USER_SESSION_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_SESSION_API)),
                "post",
                USER_SESSION_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USER_PASSWORD_API)),
                "put",
                USER_PASSWORD_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(USER_EMAIL_VERIFY_TOKEN_API)
                ),
                "post",
                USER_EMAIL_VERIFY_TOKEN_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(SEARCH_TAGS_API)),
                "get",
                SEARCH_TAGS_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(DASHBOARD_ANALYTICS_API)
                ),
                "post",
                DASHBOARD_ANALYTICS_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(TENANT_API)),
                "post",
                TENANT_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(TENANT_API)),
                "delete",
                TENANT_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(TENANT_API)),
                "get",
                TENANT_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(TENANT_THIRD_PARTY_CONFIG_API)
                ),
                "put",
                TENANT_THIRD_PARTY_CONFIG_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(TENANT_THIRD_PARTY_CONFIG_API)
                ),
                "delete",
                TENANT_THIRD_PARTY_CONFIG_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(TENANT_THIRD_PARTY_CONFIG_API)
                ),
                "get",
                TENANT_THIRD_PARTY_CONFIG_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(LIST_TENANTS_WITH_LOGIN_METHODS)
                ),
                "get",
                LIST_TENANTS_WITH_LOGIN_METHODS,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(UPDATE_TENANT_CORE_CONFIG_API)
                ),
                "put",
                UPDATE_TENANT_CORE_CONFIG_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(UPDATE_TENANT_FIRST_FACTOR_API)
                ),
                "put",
                UPDATE_TENANT_FIRST_FACTOR_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(
                        UPDATE_TENANT_REQUIRED_SECONDARY_FACTOR_API
                    )
                ),
                "put",
                UPDATE_TENANT_REQUIRED_SECONDARY_FACTOR_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(CREATE_EMAIL_PASSWORD_USER)
                ),
                "post",
                CREATE_EMAIL_PASSWORD_USER,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(CREATE_PASSWORDLESS_USER)
                ),
                "post",
                CREATE_PASSWORDLESS_USER,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(UNLINK_USER)),
                "get",
                UNLINK_USER,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(USERROLES_PERMISSIONS_API)
                ),
                "get",
                USERROLES_PERMISSIONS_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(USERROLES_PERMISSIONS_API)
                ),
                "put",
                USERROLES_PERMISSIONS_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(
                    get_api_path_with_dashboard_base(USERROLES_REMOVE_PERMISSIONS_API)
                ),
                "put",
                USERROLES_REMOVE_PERMISSIONS_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERROLES_LIST_API)),
                "get",
                USERROLES_LIST_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERROLES_ROLE_API)),
                "put",
                USERROLES_ROLE_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERROLES_ROLE_API)),
                "delete",
                USERROLES_ROLE_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERROLES_ROLE_API)),
                "get",
                USERROLES_ROLE_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERROLES_USER_API)),
                "get",
                USERROLES_USER_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERROLES_USER_API)),
                "put",
                USERROLES_USER_API,
                False,
            ),
            APIHandled(
                NormalisedURLPath(get_api_path_with_dashboard_base(USERROLES_USER_API)),
                "delete",
                USERROLES_USER_API,
                False,
            ),
        ]

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Optional[BaseResponse]:
        api_options = APIOptions(
            request,
            response,
            self.recipe_id,
            self.config,
            self.recipe_implementation,
            self.get_app_info(),
        )
        # For these APIs we dont need API key validation
        if request_id == DASHBOARD_API:
            return await handle_dashboard_api(
                self.api_implementation, api_options, user_context
            )
        if request_id == VALIDATE_KEY_API:
            return await handle_validate_key_api(
                self.api_implementation, api_options, user_context
            )
        if request_id == SIGN_IN_API:
            return await handle_emailpassword_signin_api(
                self.api_implementation, api_options, user_context
            )

        # Do API key validation for the remaining APIs
        api_function: Optional[
            Callable[
                [APIInterface, str, APIOptions, Dict[str, Any]], Awaitable[APIResponse]
            ]
        ] = None
        if request_id == USERS_LIST_GET_API:
            api_function = handle_users_get_api
        elif request_id == USERS_COUNT_API:
            api_function = handle_users_count_get_api
        elif request_id == USER_API:
            if method == "get":
                api_function = handle_user_get
            if method == "delete":
                api_function = handle_user_delete
            if method == "put":
                api_function = handle_user_put
        elif request_id == USER_EMAIL_VERIFY_API:
            if method == "get":
                api_function = handle_user_email_verify_get
            if method == "put":
                api_function = handle_user_email_verify_put
        elif request_id == USER_METADATA_API:
            if method == "get":
                api_function = handle_metadata_get
            if method == "put":
                api_function = handle_metadata_put
        elif request_id == USER_SESSION_API:
            if method == "get":
                api_function = handle_sessions_get
            if method == "post":
                api_function = handle_user_sessions_post
        elif request_id == USER_PASSWORD_API:
            api_function = handle_user_password_put
        elif request_id == USER_EMAIL_VERIFY_TOKEN_API:
            api_function = handle_email_verify_token_post
        elif request_id == SIGN_OUT_API:
            api_function = handle_emailpassword_signout_api
        elif request_id == SEARCH_TAGS_API:
            api_function = handle_get_tags
        elif request_id == DASHBOARD_ANALYTICS_API:
            if method == "post":
                api_function = handle_analytics_post
        elif request_id == TENANT_API:
            if method == "post":
                api_function = create_tenant
            if method == "delete":
                api_function = delete_tenant_api
            if method == "get":
                api_function = get_tenant_info
        elif request_id == TENANT_THIRD_PARTY_CONFIG_API:
            if method == "put":
                api_function = handle_create_or_update_third_party_config
            if method == "delete":
                api_function = delete_third_party_config_api
            if method == "get":
                api_function = get_third_party_config
        elif request_id == LIST_TENANTS_WITH_LOGIN_METHODS:
            api_function = list_all_tenants_with_login_methods
        elif request_id == UPDATE_TENANT_CORE_CONFIG_API:
            api_function = update_tenant_core_config
        elif request_id == UPDATE_TENANT_FIRST_FACTOR_API:
            api_function = update_tenant_first_factor
        elif request_id == UPDATE_TENANT_REQUIRED_SECONDARY_FACTOR_API:
            api_function = update_tenant_secondary_factor
        elif request_id == CREATE_EMAIL_PASSWORD_USER:
            api_function = create_email_password_user
        elif request_id == CREATE_PASSWORDLESS_USER:
            api_function = create_passwordless_user
        elif request_id == UNLINK_USER:
            api_function = handle_user_unlink_get
        elif request_id == USERROLES_LIST_API:
            api_function = get_all_roles_api
        elif request_id == USERROLES_PERMISSIONS_API:
            api_function = get_permissions_for_role_api
        elif request_id == USERROLES_REMOVE_PERMISSIONS_API:
            api_function = remove_permissions_from_role_api
        elif request_id == USERROLES_ROLE_API:
            if method == "put":
                api_function = create_role_or_add_permissions_api
            if method == "delete":
                api_function = delete_role_api
            if method == "get":
                api_function = get_all_roles_api
        elif request_id == USERROLES_USER_API:
            if method == "get":
                api_function = get_roles_for_user_api
            if method == "put":
                api_function = add_role_to_user_api
            if method == "delete":
                api_function = remove_user_role_api

        if api_function is not None:
            return await api_key_protector(
                self.api_implementation,
                tenant_id,
                api_options,
                api_function,
                user_context,
            )

        return None

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
        api_key: Optional[str],
        admins: Optional[List[str]] = None,
        override: Optional[InputOverrideConfig] = None,
    ):
        def func(app_info: AppInfo):
            if DashboardRecipe.__instance is None:
                DashboardRecipe.__instance = DashboardRecipe(
                    DashboardRecipe.recipe_id,
                    app_info,
                    api_key,
                    admins,
                    override,
                )
                return DashboardRecipe.__instance
            raise Exception(
                None,
                "Dashboard recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def get_instance() -> DashboardRecipe:
        if DashboardRecipe.__instance is not None:
            return DashboardRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        DashboardRecipe.__instance = None
