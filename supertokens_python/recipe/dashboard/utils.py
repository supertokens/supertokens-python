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

from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Union

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
from supertokens_python.recipe.thirdpartyemailpassword.asyncio import (
    get_user_by_id as tpep_get_user_by_id,
)
from supertokens_python.recipe.thirdpartypasswordless.asyncio import (
    get_user_by_id as tppless_get_user_by_id,
)
from supertokens_python.utils import Awaitable

from ...normalised_url_path import NormalisedURLPath
from ...supertokens import AppInfo
from .constants import (
    DASHBOARD_API,
    USER_API,
    USER_EMAIL_VERIFY_API,
    USER_METADATA_API,
    USER_SESSION_API,
    USERS_COUNT_API,
    USERS_LIST_GET_API,
    VALIDATE_KEY_API,
    USER_EMAIL_VERIFY_TOKEN_API,
    USER_PASSWORD_API,
)

if TYPE_CHECKING:
    from .interfaces import APIInterface, RecipeInterface


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
        api_key: str,
        override: OverrideConfig,
    ):
        self.api_key = api_key
        self.override = override


def validate_and_normalise_user_input(
    # app_info: AppInfo,
    api_key: str,
    override: Optional[InputOverrideConfig] = None,
) -> DashboardConfig:
    if api_key.strip() == "":
        raise Exception("apiKey provided to Dashboard recipe cannot be empty")

    if override is None:
        override = InputOverrideConfig()

    return DashboardConfig(
        api_key,
        OverrideConfig(
            functions=override.functions,
            apis=override.apis,
        ),
    )


def is_api_path(path: NormalisedURLPath, app_info: AppInfo) -> bool:
    dashboard_recipe_base_path = app_info.api_base_path.append(
        NormalisedURLPath(DASHBOARD_API)
    )

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

    return None


def is_valid_recipe_id(recipe_id: str) -> bool:
    return recipe_id in ("emailpassword", "thirdparty", "passwordless")


async def get_user_for_recipe_id(user_id: str, recipe_id: str) -> Dict[str, Any]:
    user: Optional[Dict[str, Any]] = None
    recipe: Optional[str] = None

    async def update_user(
        get_user_func1: Callable[[str], Awaitable[Any]],
        get_user_func2: Callable[[str], Awaitable[Any]],
        recipe1: str,
        recipe2: str,
    ):
        nonlocal user, user_id, recipe

        try:
            user_response = await get_user_func1(user_id)  # type: ignore

            if user_response is not None:
                user = {
                    **user_response.__dict__,
                    "firstName": "",
                    "lastName": "",
                }
                recipe = recipe1
        except Exception:
            pass

        if user is None:
            try:
                user_response = await get_user_func2(user_id)

                if user_response is not None:
                    user = {
                        **user_response.__dict__,
                        "firstName": "",
                        "lastName": "",
                    }
                    recipe = recipe2
            except Exception:
                pass

    if recipe_id == EmailPasswordRecipe.recipe_id:
        await update_user(
            ep_get_user_by_id,
            tpep_get_user_by_id,
            "emailpassword",
            "thirdpartyemailpassword",
        )

    elif recipe_id == ThirdPartyRecipe.recipe_id:
        await update_user(
            tp_get_user_by_idx,
            tpep_get_user_by_id,
            "thirdparty",
            "thirdpartyemailpassword",
        )

    elif recipe_id == PasswordlessRecipe.recipe_id:
        await update_user(
            pless_get_user_by_id,
            tppless_get_user_by_id,
            "passwordless",
            "thirdpartypasswordless",
        )

    assert isinstance(user, dict)  # TODO shouldn't be required
    user.update({"id": user.pop("user_id"), "timeJoined": user.pop("time_joined")})  # type: ignore # TODO shouldn't be required

    return {"user": user, "recipe": recipe}
