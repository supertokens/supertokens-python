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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Union

from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.ingredients.smsdelivery.types import SMSDeliveryConfig
from supertokens_python.recipe.thirdparty.provider import Provider
from typing_extensions import Literal

from .. import passwordless, thirdparty
from . import exceptions as ex
from . import utils
from .emaildelivery import services as emaildelivery_services
from .recipe import ThirdPartyPasswordlessRecipe
from .smsdelivery import services as smsdelivery_services
from .types import EmailTemplateVars, SMSTemplateVars

InputOverrideConfig = utils.InputOverrideConfig
exceptions = ex
ContactConfig = passwordless.ContactConfig
PhoneOrEmailInput = passwordless.PhoneOrEmailInput
Apple = thirdparty.Apple
Discord = thirdparty.Discord
Facebook = thirdparty.Facebook
Github = thirdparty.Github
Google = thirdparty.Google
GoogleWorkspaces = thirdparty.GoogleWorkspaces
ContactPhoneOnlyConfig = passwordless.ContactPhoneOnlyConfig
ContactEmailOnlyConfig = passwordless.ContactEmailOnlyConfig
ContactEmailOrPhoneConfig = passwordless.ContactEmailOrPhoneConfig
SMTPService = emaildelivery_services.SMTPService
TwilioService = smsdelivery_services.TwilioService
SuperTokensSMSService = smsdelivery_services.SuperTokensSMSService

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from ...recipe_module import RecipeModule


def init(
    contact_config: ContactConfig,
    flow_type: Literal[
        "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
    ],
    get_custom_user_input_code: Union[
        Callable[[Dict[str, Any]], Awaitable[str]], None
    ] = None,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    sms_delivery: Union[SMSDeliveryConfig[SMSTemplateVars], None] = None,
    override: Union[InputOverrideConfig, None] = None,
    providers: Union[List[Provider], None] = None,
) -> Callable[[AppInfo], RecipeModule]:
    return ThirdPartyPasswordlessRecipe.init(
        contact_config,
        flow_type,
        get_custom_user_input_code,
        email_delivery,
        sms_delivery,
        override,
        providers,
    )
