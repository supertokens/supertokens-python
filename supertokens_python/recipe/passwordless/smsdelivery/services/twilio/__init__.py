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

from supertokens_python.ingredients.smsdelivery.service.twilio import (
    ServiceInterface, SMSDeliveryTwilioConfig, normalize_twilio_config)
from supertokens_python.ingredients.smsdelivery.types import \
    SMSDeliveryInterface
from supertokens_python.recipe.passwordless.types import \
    TypePasswordlessSmsDeliveryInput

from twilio.rest import Client  # type: ignore

from .implementation import ServiceImplementation


class TwilioService(SMSDeliveryInterface[TypePasswordlessSmsDeliveryInput]):
    service_implementation: ServiceInterface[TypePasswordlessSmsDeliveryInput]

    def __init__(self, config: SMSDeliveryTwilioConfig[TypePasswordlessSmsDeliveryInput]) -> None:
        self.config = normalize_twilio_config(config)
        if config.twilio_config.opts:
            _otps = config.twilio_config.opts
        else:
            _otps = {}
        self.twilio_client = Client(  # type: ignore
            config.twilio_config.account_sid,
            config.twilio_config.auth_token,
            # TODO: _opts? (Twilio python sdk doesn't seem to provide a way to pass options. Find a way)
            # **_otps
        )
        oi = ServiceImplementation(self.twilio_client)  # type: ignore
        self.service_implementation = oi if config.override is None else config.override(oi)

    async def send_sms(self, input_: TypePasswordlessSmsDeliveryInput, user_context: Dict[str, Any]) -> None:
        content = await self.service_implementation.get_content(input_, user_context)
        if self.config.twilio_config.input_from:
            await self.service_implementation.send_raw_sms(
                content,
                user_context,  # TODO: should be part of sms_input
                from_=self.config.twilio_config.input_from,
            )
        else:
            await self.service_implementation.send_raw_sms(
                content,
                user_context,
                sid=self.config.twilio_config.sid,
            )
