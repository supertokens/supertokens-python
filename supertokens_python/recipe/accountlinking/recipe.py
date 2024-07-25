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
from typing import Any, Dict, List, Union, TYPE_CHECKING, Optional, Callable
from supertokens_python.supertokens import Supertokens

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import APIHandled, RecipeModule

from supertokens_python.exceptions import SuperTokensError, raise_general_exception

from .types import (
    RecipeLevelUser,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
    AccountInfoWithRecipeIdAndUserId,
    InputOverrideConfig,
)

from .interfaces import RecipeInterface

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.types import AccountLinkingUser
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.framework import BaseRequest, BaseResponse


class AccountLinkingRecipe(RecipeModule):
    recipe_id = "accountlinking"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        on_account_linked: Optional[
            Callable[[AccountLinkingUser, RecipeLevelUser, Dict[str, Any]], None]
        ] = None,
        should_do_automatic_account_linking: Optional[
            Callable[
                [
                    AccountInfoWithRecipeIdAndUserId,
                    Optional[AccountLinkingUser],
                    Optional[SessionContainer],
                    str,
                    Dict[str, Any],
                ],
                Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink],
            ]
        ] = None,
        override: Optional[InputOverrideConfig] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.recipe_implementation: RecipeInterface
        raise Exception("TODO: to implement")

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return False

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
        on_account_linked: Optional[
            Callable[[AccountLinkingUser, RecipeLevelUser, Dict[str, Any]], None]
        ] = None,
        should_do_automatic_account_linking: Optional[
            Callable[
                [
                    AccountInfoWithRecipeIdAndUserId,
                    Optional[AccountLinkingUser],
                    Optional[SessionContainer],
                    str,
                    Dict[str, Any],
                ],
                Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink],
            ]
        ] = None,
        override: Optional[InputOverrideConfig] = None,
    ):
        def func(app_info: AppInfo):
            if AccountLinkingRecipe.__instance is None:
                AccountLinkingRecipe.__instance = AccountLinkingRecipe(
                    AccountLinkingRecipe.recipe_id,
                    app_info,
                    on_account_linked,
                    should_do_automatic_account_linking,
                    override,
                )
                return AccountLinkingRecipe.__instance
            raise Exception(
                None,
                "Accountlinking recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def get_instance() -> AccountLinkingRecipe:
        if AccountLinkingRecipe.__instance is None:
            AccountLinkingRecipe.init()(Supertokens.get_instance().app_info)

        assert AccountLinkingRecipe.__instance is not None
        return AccountLinkingRecipe.__instance

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        AccountLinkingRecipe.__instance = None
