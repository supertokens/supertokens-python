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

from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Union, List

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest

from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.asyncio import (
    get_user_by_id as ep_get_user_by_id,
)
from supertokens_python.recipe.passwordless import PasswordlessRecipe
from supertokens_python.recipe.passwordless.asyncio import (
    get_user_by_id as pless_get_user_by_id,
)
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.asyncio import (
    get_user_by_id as tp_get_user_by_idx,
)
from supertokens_python.recipe.thirdpartyemailpassword import (
    ThirdPartyEmailPasswordRecipe,
)
from supertokens_python.recipe.thirdpartyemailpassword.asyncio import (
    get_user_by_id as tpep_get_user_by_id,
)
from supertokens_python.recipe.thirdpartypasswordless import (
    ThirdPartyPasswordlessRecipe,
)
from supertokens_python.recipe.thirdpartypasswordless.asyncio import (
    get_user_by_id as tppless_get_user_by_id,
)
from supertokens_python.types import User
from supertokens_python.utils import Awaitable, log_debug_message, normalise_email

from ...normalised_url_path import NormalisedURLPath
from .constants import (
    DASHBOARD_ANALYTICS_API,
    DASHBOARD_API,
    SIGN_OUT_API,
    SIGN_IN_API,
    SEARCH_TAGS_API,
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
    user_id: str
    time_joined: int
    recipe_id: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    tp_info: Optional[Dict[str, Any]] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    tenant_ids: List[str]

    def from_user(
        self,
        user: User,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ):
        self.first_name = first_name
        self.last_name = last_name

        self.user_id = user.user_id
        # from_user() is called in /api/users (note extra s)
        # here we DashboardUsersGetResponse() doesn't maintain
        # recipe id for each user on its own. That's why we need
        # to set self.recipe_id here.
        self.recipe_id = user.recipe_id
        self.time_joined = user.time_joined
        self.email = user.email
        self.phone_number = user.phone_number
        self.tp_info = (
            None if user.third_party_info is None else user.third_party_info.__dict__
        )
        self.tenant_ids = user.tenant_ids

        return self

    def from_dict(
        self,
        user_obj_dict: Dict[str, Any],
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ):
        self.first_name = first_name
        self.last_name = last_name

        self.user_id = user_obj_dict["user_id"]
        # from_dict() is used in `/api/user` where
        # recipe_id is already passed seperately to
        # GetUserForRecipeIdResult object
        # So we set recipe_id to None here
        self.recipe_id = None
        self.time_joined = user_obj_dict["time_joined"]
        self.tenant_ids = user_obj_dict.get("tenant_ids", [])

        self.email = user_obj_dict.get("email")
        self.phone_number = user_obj_dict.get("phone_number")
        self.tp_info = (
            None
            if user_obj_dict.get("third_party_info") is None
            else user_obj_dict["third_party_info"].__dict__
        )

        return self

    def to_json(self) -> Dict[str, Any]:
        user_json: Dict[str, Any] = {
            "id": self.user_id,
            "timeJoined": self.time_joined,
            "tenantIds": self.tenant_ids,
        }
        if self.tp_info is not None:
            user_json["thirdParty"] = {
                "id": self.tp_info["id"],
                "userId": self.tp_info["user_id"],
            }
        if self.phone_number is not None:
            user_json["phoneNumber"] = self.phone_number
        if self.email is not None:
            user_json["email"] = self.email
        if self.first_name is not None:
            user_json["firstName"] = self.first_name
        if self.last_name is not None:
            user_json["lastName"] = self.last_name

        if self.recipe_id is not None:
            return {
                "recipeId": self.recipe_id,
                "user": user_json,
            }
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


def is_valid_recipe_id(recipe_id: str) -> bool:
    return recipe_id in ("emailpassword", "thirdparty", "passwordless")


class GetUserForRecipeIdResult:
    def __init__(self, user: UserWithMetadata, recipe: str):
        self.user = user
        self.recipe = recipe


if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.types import User as EmailPasswordUser
    from supertokens_python.recipe.passwordless.types import User as PasswordlessUser
    from supertokens_python.recipe.thirdparty.types import User as ThirdPartyUser
    from supertokens_python.recipe.thirdpartyemailpassword.types import (
        User as ThirdPartyEmailPasswordUser,
    )
    from supertokens_python.recipe.thirdpartypasswordless.types import (
        User as ThirdPartyPasswordlessUser,
    )

    GetUserResult = Union[
        EmailPasswordUser,
        ThirdPartyUser,
        PasswordlessUser,
        None,
        ThirdPartyEmailPasswordUser,
        ThirdPartyPasswordlessUser,
    ]


async def get_user_for_recipe_id(
    user_id: str, recipe_id: str
) -> Optional[GetUserForRecipeIdResult]:
    user: Optional[UserWithMetadata] = None
    recipe: Optional[str] = None

    async def update_user_dict(
        get_user_func1: Callable[[str], Awaitable[GetUserResult]],
        get_user_func2: Callable[[str], Awaitable[GetUserResult]],
        recipe1: str,
        recipe2: str,
    ):
        nonlocal user, user_id, recipe

        try:
            recipe_user = await get_user_func1(user_id)  # type: ignore

            if recipe_user is not None:
                user = UserWithMetadata().from_dict(
                    recipe_user.__dict__, first_name="", last_name=""
                )
                recipe = recipe1
        except Exception:
            pass

        if user is None:
            try:
                recipe_user = await get_user_func2(user_id)

                if recipe_user is not None:
                    user = UserWithMetadata().from_dict(
                        recipe_user.__dict__, first_name="", last_name=""
                    )
                    recipe = recipe2
            except Exception:
                pass

    if recipe_id == EmailPasswordRecipe.recipe_id:
        await update_user_dict(
            ep_get_user_by_id,
            tpep_get_user_by_id,
            "emailpassword",
            "thirdpartyemailpassword",
        )

    elif recipe_id == ThirdPartyRecipe.recipe_id:
        await update_user_dict(
            tp_get_user_by_idx,
            tpep_get_user_by_id,
            "thirdparty",
            "thirdpartyemailpassword",
        )

    elif recipe_id == PasswordlessRecipe.recipe_id:
        await update_user_dict(
            pless_get_user_by_id,
            tppless_get_user_by_id,
            "passwordless",
            "thirdpartypasswordless",
        )

    if user is not None and recipe is not None:
        return GetUserForRecipeIdResult(user, recipe)

    return None


def is_recipe_initialised(recipeId: str) -> bool:
    isRecipeInitialised: bool = False

    if recipeId == EmailPasswordRecipe.recipe_id:
        try:
            EmailPasswordRecipe.get_instance()
            isRecipeInitialised = True
        except Exception:
            pass

        if not isRecipeInitialised:
            try:
                ThirdPartyEmailPasswordRecipe.get_instance()
                isRecipeInitialised = True
            except Exception:
                pass

    elif recipeId == PasswordlessRecipe.recipe_id:
        try:
            PasswordlessRecipe.get_instance()
            isRecipeInitialised = True
        except Exception:
            pass

        if not isRecipeInitialised:
            try:
                ThirdPartyPasswordlessRecipe.get_instance()
                isRecipeInitialised = True
            except Exception:
                pass

    elif recipeId == ThirdPartyRecipe.recipe_id:
        try:
            ThirdPartyRecipe.get_instance()
            isRecipeInitialised = True
        except Exception:
            pass

        if not isRecipeInitialised:
            try:
                ThirdPartyEmailPasswordRecipe.get_instance()
                isRecipeInitialised = True
            except Exception:
                pass

        if not isRecipeInitialised:
            try:
                ThirdPartyPasswordlessRecipe.get_instance()
                isRecipeInitialised = True
            except Exception:
                pass

    return isRecipeInitialised


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
