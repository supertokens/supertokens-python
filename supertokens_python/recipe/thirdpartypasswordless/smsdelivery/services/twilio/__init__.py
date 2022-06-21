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

from typing import Any, Dict

from supertokens_python.ingredients.smsdelivery.services.twilio import \
    SMSDeliveryTwilioConfig
from supertokens_python.ingredients.smsdelivery.types import \
    SMSDeliveryInterface
from supertokens_python.recipe.passwordless.smsdelivery.services.twilio import \
    TwilioService as PlessTwilioService

from ....types import TypeThirdPartyPasswordlessSmsDeliveryInput


class TwilioService(SMSDeliveryInterface[TypeThirdPartyPasswordlessSmsDeliveryInput]):
    pless_twilio_service: PlessTwilioService

    def __init__(self, config: SMSDeliveryTwilioConfig[TypeThirdPartyPasswordlessSmsDeliveryInput]) -> None:
        self.pless_twilio_service = PlessTwilioService(config)

    async def send_sms(self, input_: TypeThirdPartyPasswordlessSmsDeliveryInput, user_context: Dict[str, Any]) -> None:
        await self.pless_twilio_service.send_sms(input_, user_context)
