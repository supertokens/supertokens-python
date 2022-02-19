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
from . import utils
from .recipe import EmailPasswordRecipe

exceptions = ex
InputOverrideConfig = utils.InputOverrideConfig
InputResetPasswordUsingTokenFeature = utils.InputResetPasswordUsingTokenFeature
InputEmailVerificationConfig = utils.InputEmailVerificationConfig
InputSignUpFeature = utils.InputSignUpFeature
InputFormField = utils.InputFormField

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from ...recipe_module import RecipeModule


def init(sign_up_feature: Union[utils.InputSignUpFeature, None] = None,
         reset_password_using_token_feature: Union[
             utils.InputResetPasswordUsingTokenFeature, None] = None,
         email_verification_feature: Union[utils.InputEmailVerificationConfig, None] = None,
         override: Union[utils.InputOverrideConfig, None] = None) -> Callable[[AppInfo], RecipeModule]:
    return EmailPasswordRecipe.init(
        sign_up_feature,
        reset_password_using_token_feature,
        email_verification_feature,
        override
    )
