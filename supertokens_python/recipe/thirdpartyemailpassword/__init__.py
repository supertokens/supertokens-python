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

from typing import TYPE_CHECKING, Callable, List, Union

from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.recipe.thirdparty import provider
from supertokens_python.recipe.thirdpartyemailpassword.types import EmailTemplateVars
from supertokens_python.ingredients.emaildelivery import types as emaildelivery_types
from . import types

from .. import emailpassword
from . import exceptions as ex
from . import utils
from .emaildelivery import services as emaildelivery_services
from .recipe import ThirdPartyEmailPasswordRecipe

InputOverrideConfig = utils.InputOverrideConfig
exceptions = ex
InputSignUpFeature = emailpassword.InputSignUpFeature
ProviderInput = provider.ProviderInput
ProviderConfig = provider.ProviderConfig
ProviderClientConfig = provider.ProviderClientConfig
ProviderConfigForClientType = provider.ProviderConfigForClient
SMTPService = emaildelivery_services.SMTPService

EmailDeliveryInterface = emaildelivery_types.EmailDeliveryInterface
PasswordResetEmailTemplateVars = types.PasswordResetEmailTemplateVars

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from ...recipe_module import RecipeModule


def init(
    sign_up_feature: Union[InputSignUpFeature, None] = None,
    override: Union[InputOverrideConfig, None] = None,
    providers: Union[List[ProviderInput], None] = None,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
) -> Callable[[AppInfo], RecipeModule]:
    return ThirdPartyEmailPasswordRecipe.init(
        sign_up_feature,
        override,
        providers,
        email_delivery,
    )
