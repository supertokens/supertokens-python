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

from typing import TYPE_CHECKING, Callable

from . import exceptions as ex
from . import utils
from .emaildelivery import services as emaildelivery_services
from .recipe import EmailVerificationRecipe

InputOverrideConfig = utils.OverrideConfig
ParentRecipeEmailVerificationConfig = utils.ParentRecipeEmailVerificationConfig
exception = ex
SMTPService = emaildelivery_services.SMTPService


if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from ...recipe_module import RecipeModule


def init(config: ParentRecipeEmailVerificationConfig) -> Callable[[AppInfo], RecipeModule]:
    return EmailVerificationRecipe.init(config)
