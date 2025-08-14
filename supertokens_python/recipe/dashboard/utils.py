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

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest

from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.passwordless import PasswordlessRecipe
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.types import RecipeUserId, User
from supertokens_python.utils import log_debug_message, normalise_email

from ...normalised_url_path import NormalisedURLPath
from .constants import (
    DASHBOARD_ANALYTICS_API,
    DASHBOARD_API,
    SEARCH_TAGS_API,
    SIGN_IN_API,
    SIGN_OUT_API,
    USER_API,
    USER_EMAIL_VERIFY_API,
    USER_EMAIL_VERIFY_TOKEN_API,
    USER_METADATA_API,
    USER_PASSWORD_API,
    USER_SESSION_API,
    USERS_COUNT_API,
    USERS_LIST_GET_API,
    VALIDATE_KEY_API,
)

if TYPE_CHECKING:
    from .interfaces import APIInterface, RecipeInterface


class UserWithMetadata:
    user: User
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    def from_user(
        self,
        user: User,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ):
        self.first_name = first_name or ""
        self.last_name = last_name or ""
        self.user = user
        return self

    def to_json(self) -> Dict[str, Any]:
        user_json = self.user.to_json()
        user_json["firstName"] = self.first_name
        user_json["lastName"] = self.last_name
        return user_json


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class DashboardConfig:
    def __init__(
        self,
        api_key: Optional[str],
        admins: Optional[List[str]],
        override: OverrideConfig,
        auth_mode: str,
    ):
        self.api_key = api_key
        self.admins = admins
        self.override = override
        self.auth_mode = auth_mode


def validate_and_normalise_user_input(
    # app_info: AppInfo,
    api_key: Union[str, None],
    admins: Optional[List[str]],
    override: Optional[InputOverrideConfig] = None,
) -> DashboardConfig:
    if override is None:
        override = InputOverrideConfig()

    if api_key is not None and admins is not None:
        log_debug_message(
            "User Dashboard: Providing 'admins' has no effect when using an api key."
        )

    admins = [normalise_email(a) for a in admins] if admins is not None else None

    return DashboardConfig(
        api_key,
        admins,
        OverrideConfig(
            functions=override.functions,
            apis=override.apis,
        ),
        "api-key" if api_key else "email-password",
    )


def is_api_path(path: NormalisedURLPath, base_path: NormalisedURLPath) -> bool:
    dashboard_recipe_base_path = base_path.append(NormalisedURLPath(DASHBOARD_API))

    if not path.startswith(dashboard_recipe_base_path):
        return False

    path_without_dashboard_path = path.get_as_string_dangerous().split(DASHBOARD_API)[1]

    if len(path_without_dashboard_path) > 0 and path_without_dashboard_path[0] == "/":
        path_without_dashboard_path = path_without_dashboard_path[1:]

    if path_without_dashboard_path.split("/")[0] == "api":
        return True

    return False


def get_api_if_matched(path: NormalisedURLPath, method: str) -> Optional[str]:
    path_str = path.get_as_string_dangerous()

    if path_str.endswith(VALIDATE_KEY_API) and method == "post":
        return VALIDATE_KEY_API
    if path_str.endswith(USERS_LIST_GET_API) and method == "get":
        return USERS_LIST_GET_API
    if path_str.endswith(USERS_COUNT_API) and method == "get":
        return USERS_COUNT_API
    if path_str.endswith(USER_API) and method in ("get", "delete", "put"):
        return USER_API
    if path_str.endswith(USER_EMAIL_VERIFY_API) and method in ("get", "put"):
        return USER_EMAIL_VERIFY_API
    if path_str.endswith(USER_METADATA_API) and method in ("get", "put"):
        return USER_METADATA_API
    if path_str.endswith(USER_SESSION_API) and method in ("get", "post"):
        return USER_SESSION_API
    if path_str.endswith(USER_PASSWORD_API) and method == "put":
        return USER_PASSWORD_API
    if path_str.endswith(USER_EMAIL_VERIFY_TOKEN_API) and method == "post":
        return USER_EMAIL_VERIFY_TOKEN_API
    if path_str.endswith(SIGN_IN_API) and method == "post":
        return SIGN_IN_API
    if path_str.endswith(SIGN_OUT_API) and method == "post":
        return SIGN_OUT_API
    if path_str.endswith(SEARCH_TAGS_API) and method == "get":
        return SEARCH_TAGS_API
    if path_str.endswith(DASHBOARD_ANALYTICS_API) and method == "post":
        return DASHBOARD_ANALYTICS_API

    return None


class GetUserForRecipeIdHelperResult:
    def __init__(self, user: Optional[User] = None, recipe: Optional[str] = None):
        self.user = user
        self.recipe = recipe


class GetUserForRecipeIdResult:
    def __init__(
        self, user: Optional[UserWithMetadata] = None, recipe: Optional[str] = None
    ):
        self.user = user
        self.recipe = recipe


async def get_user_for_recipe_id(
    recipe_user_id: RecipeUserId, recipe_id: str, user_context: Dict[str, Any]
) -> GetUserForRecipeIdResult:
    user_response = await _get_user_for_recipe_id(
        recipe_user_id, recipe_id, user_context
    )

    user = None
    if user_response.user is not None:
        user = UserWithMetadata().from_user(
            user_response.user, first_name="", last_name=""
        )

    return GetUserForRecipeIdResult(user=user, recipe=user_response.recipe)


async def _get_user_for_recipe_id(
    recipe_user_id: RecipeUserId, recipe_id: str, user_context: Dict[str, Any]
) -> GetUserForRecipeIdHelperResult:
    recipe: Optional[
        Literal["emailpassword", "thirdparty", "passwordless", "webauthn"]
    ] = None

    user = await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
        recipe_user_id.get_as_string(), user_context
    )

    if user is None:
        return GetUserForRecipeIdHelperResult(user=None, recipe=None)

    login_method = next(
        (
            m
            for m in user.login_methods
            if m.recipe_id == recipe_id
            and m.recipe_user_id.get_as_string() == recipe_user_id.get_as_string()
        ),
        None,
    )

    if login_method is None:
        return GetUserForRecipeIdHelperResult(user=None, recipe=None)

    if recipe_id == EmailPasswordRecipe.recipe_id:
        try:
            EmailPasswordRecipe.get_instance()
            recipe = "emailpassword"
        except Exception:
            pass
    elif recipe_id == ThirdPartyRecipe.recipe_id:
        try:
            ThirdPartyRecipe.get_instance()
            recipe = "thirdparty"
        except Exception:
            pass
    elif recipe_id == PasswordlessRecipe.recipe_id:
        try:
            PasswordlessRecipe.get_instance()
            recipe = "passwordless"
        except Exception:
            pass
    elif recipe_id == WebauthnRecipe.recipe_id:
        try:
            WebauthnRecipe.get_instance()
            recipe = "webauthn"
        except Exception:
            pass

    return GetUserForRecipeIdHelperResult(user=user, recipe=recipe)


async def validate_api_key(
    req: BaseRequest, config: DashboardConfig, _user_context: Dict[str, Any]
) -> bool:
    api_key_header_value = req.get_header("authorization")
    if not api_key_header_value:
        return False
    # We receieve the api key as `Bearer API_KEY`, this retrieves just the key
    api_key_header_value = api_key_header_value.split(" ")[1]
    return api_key_header_value == config.api_key


def get_api_path_with_dashboard_base(path: str) -> str:
    return DASHBOARD_API + path
