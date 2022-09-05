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

from typing import TYPE_CHECKING, Callable, Union


from . import exceptions as ex
from . import providers, utils
from .recipe import ThirdPartyRecipe

InputOverrideConfig = utils.InputOverrideConfig
SignInAndUpFeature = utils.SignInAndUpFeature
Apple = providers.Apple
Discord = providers.Discord
Facebook = providers.Facebook
Github = providers.Github
Google = providers.Google
GoogleWorkspaces = providers.GoogleWorkspaces
exceptions = ex

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from ...recipe_module import RecipeModule


def init(
    sign_in_and_up_feature: SignInAndUpFeature,
    override: Union[InputOverrideConfig, None] = None,
) -> Callable[[AppInfo], RecipeModule]:
    return ThirdPartyRecipe.init(sign_in_and_up_feature, override)
