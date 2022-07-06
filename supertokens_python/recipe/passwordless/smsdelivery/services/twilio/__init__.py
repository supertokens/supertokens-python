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

from typing import Any, Dict, Callable, Union, TypeVar

from supertokens_python.ingredients.smsdelivery.services.twilio import (
    normalize_twilio_settings,
)
from supertokens_python.ingredients.smsdelivery.types import (
    SMSDeliveryInterface,
    TwilioServiceInterface,
    TwilioSettings,
)
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginSMSTemplateVars,
)

from twilio.rest import Client  # type: ignore

from .service_implementation import ServiceImplementation

_T = TypeVar("_T")


class TwilioService(SMSDeliveryInterface[PasswordlessLoginSMSTemplateVars]):
    service_implementation: TwilioServiceInterface[PasswordlessLoginSMSTemplateVars]

    def __init__(
        self,
        twilio_settings: TwilioSettings,
        override: Union[
            Callable[[TwilioServiceInterface[_T]], TwilioServiceInterface[_T]], None
        ] = None,
    ) -> None:
        self.config = normalize_twilio_settings(twilio_settings)
        otps = twilio_settings.opts if twilio_settings.opts else {}
        self.twilio_client = Client(  # type: ignore
            twilio_settings.account_sid, twilio_settings.auth_token, **otps
        )
        oi = ServiceImplementation(self.twilio_client)  # type: ignore
        self.service_implementation = oi if override is None else override(oi)

    async def send_sms(
        self,
        template_vars: PasswordlessLoginSMSTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        content = await self.service_implementation.get_content(
            template_vars, user_context
        )
        await self.service_implementation.send_raw_sms(
            content,
            user_context,
            from_=self.config.from_,
            messaging_service_sid=self.config.messaging_service_sid,
        )
