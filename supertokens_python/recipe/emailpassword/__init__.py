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

from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.recipe.emailpassword.types import EmailTemplateVars

from . import exceptions as ex
from . import utils
from .emaildelivery import services as emaildelivery_services
from .recipe import EmailPasswordRecipe

exceptions = ex
InputOverrideConfig = utils.InputOverrideConfig
InputResetPasswordUsingTokenFeature = utils.InputResetPasswordUsingTokenFeature
InputSignUpFeature = utils.InputSignUpFeature
InputFormField = utils.InputFormField
SMTPService = emaildelivery_services.SMTPService

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from ...recipe_module import RecipeModule


def init(
    sign_up_feature: Union[utils.InputSignUpFeature, None] = None,
    reset_password_using_token_feature: Union[
        utils.InputResetPasswordUsingTokenFeature, None
    ] = None,
    override: Union[utils.InputOverrideConfig, None] = None,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
) -> Callable[[AppInfo], RecipeModule]:
    return EmailPasswordRecipe.init(
        sign_up_feature,
        reset_password_using_token_feature,
        override,
        email_delivery,
    )
