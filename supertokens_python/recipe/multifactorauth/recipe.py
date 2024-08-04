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

from typing import Optional

from supertokens_python.exceptions import raise_general_exception
from supertokens_python.recipe.multifactorauth.interfaces import RecipeInterface
from supertokens_python.recipe.multifactorauth.types import TypeInput
from supertokens_python.recipe_module import RecipeModule
from supertokens_python.supertokens import AppInfo, Supertokens


class MultiFactorAuthRecipe(RecipeModule):
    recipe_id = "multifactorauth"
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo, config: Optional[TypeInput]):
        self.recipe_implementation: RecipeInterface

    @staticmethod
    def init(config: Optional[TypeInput] = None):
        def func(app_info: AppInfo):
            if MultiFactorAuthRecipe.__instance is None:
                MultiFactorAuthRecipe.__instance = MultiFactorAuthRecipe(
                    MultiFactorAuthRecipe.recipe_id, app_info, config
                )
                return MultiFactorAuthRecipe.__instance
            raise_general_exception(
                "MultiFactorAuthRecipe recipe has already been initialised. Please check "
                "your code for bugs."
            )

        return func

    @staticmethod
    def get_instance_or_throw_error() -> MultiFactorAuthRecipe:
        if MultiFactorAuthRecipe.__instance is None:
            raise Exception(
                "No instance of MultiFactorAuthRecipe found. Did you forget to call the MultiFactorAuth.init method?"
            )
        return MultiFactorAuthRecipe.__instance

    @staticmethod
    def get_instance() -> MultiFactorAuthRecipe:
        if MultiFactorAuthRecipe.__instance is None:
            MultiFactorAuthRecipe.init()(Supertokens.get_instance().app_info)

        assert MultiFactorAuthRecipe.__instance is not None
        return MultiFactorAuthRecipe.__instance
