# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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
from typing import Callable, Dict, Any, Union, Optional, List, TYPE_CHECKING
from typing_extensions import Literal
from supertokens_python.recipe.accountlinking.interfaces import (
    AccountInfo,
    RecipeInterface,
)

if TYPE_CHECKING:
    from supertokens_python.types import (
        RecipeUserId,
        ThirdPartyInfo,
        AccountLinkingUser,
    )
    from supertokens_python.recipe.session import SessionContainer


class AccountInfoWithRecipeId(AccountInfo):
    def __init__(
        self,
        recipe_id: Literal["emailpassword", "thirdparty", "passwordless"],
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        third_party: Optional[ThirdPartyInfo] = None,
    ):
        super().__init__(email, phone_number, third_party)
        self.recipe_id = recipe_id


class RecipeLevelUser(AccountInfoWithRecipeId):
    def __init__(
        self,
        tenant_ids: List[str],
        time_joined: int,
        recipe_id: Literal["emailpassword", "thirdparty", "passwordless"],
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        third_party: Optional[ThirdPartyInfo] = None,
    ):
        super().__init__(recipe_id, email, phone_number, third_party)
        self.tenant_ids = tenant_ids
        self.time_joined = time_joined
        self.recipe_id = recipe_id


class AccountInfoWithRecipeIdAndUserId(RecipeLevelUser):
    def __init__(
        self,
        recipe_user_id: Optional[RecipeUserId],
        tenant_ids: List[str],
        time_joined: int,
        recipe_id: Literal["emailpassword", "thirdparty", "passwordless"],
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        third_party: Optional[ThirdPartyInfo] = None,
    ):
        super().__init__(
            tenant_ids, time_joined, recipe_id, email, phone_number, third_party
        )
        self.recipe_user_id = recipe_user_id


class ShouldNotAutomaticallyLink:
    def __init__(self):
        self.should_automatically_link = False


class ShouldAutomaticallyLink:
    def __init__(self, should_require_verification: bool):
        self.should_automatically_link = True
        self.should_require_verification = should_require_verification


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
    ):
        self.functions = functions


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
    ):
        self.functions = functions


class AccountLinkingConfig:
    def __init__(
        self,
        on_account_linked: Callable[
            [AccountLinkingUser, RecipeLevelUser, Dict[str, Any]], None
        ],
        should_do_automatic_account_linking: Callable[
            [
                AccountInfoWithRecipeIdAndUserId,
                Optional[AccountLinkingUser],
                Optional[SessionContainer],
                str,
                Dict[str, Any],
            ],
            Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink],
        ],
        override: OverrideConfig,
    ):
        self.on_account_linked = on_account_linked
        self.should_do_automatic_account_linking = should_do_automatic_account_linking
        self.override = override
