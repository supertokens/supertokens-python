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

from typing import Any, Dict, Callable, Union

from supertokens_python.ingredients.smsdelivery.types import (
    SMSDeliveryInterface,
    TwilioServiceInterface,
    TwilioSettings,
)
from supertokens_python.recipe.passwordless.smsdelivery.services.twilio import (
    TwilioService as PlessTwilioService,
)

from ....types import SMSTemplateVars


class TwilioService(SMSDeliveryInterface[SMSTemplateVars]):
    pless_twilio_service: PlessTwilioService

    def __init__(
        self,
        twilio_settings: TwilioSettings,
        override: Union[
            Callable[
                [TwilioServiceInterface[SMSTemplateVars]],
                TwilioServiceInterface[SMSTemplateVars],
            ],
            None,
        ] = None,
    ) -> None:
        self.pless_twilio_service = PlessTwilioService(twilio_settings, override)

    async def send_sms(
        self, template_vars: SMSTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        await self.pless_twilio_service.send_sms(template_vars, user_context)
