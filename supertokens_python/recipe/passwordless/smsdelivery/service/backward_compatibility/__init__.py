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

import json
from os import environ
from typing import Awaitable, Callable, Union

from httpx import AsyncClient
from supertokens_python.ingredients.smsdelivery.service.supertokens import \
    SUPERTOKENS_SMS_SERVICE_URL
from supertokens_python.ingredients.smsdelivery.types import \
    SMSDeliveryInterface
from supertokens_python.logger import log_debug_message
from supertokens_python.supertokens import AppInfo

from ....types import TypePasswordlessSmsDeliveryInput


def default_create_and_send_custom_sms(app_info: AppInfo) -> Callable[[TypePasswordlessSmsDeliveryInput], Awaitable[None]]:
    async def func(sms_input: TypePasswordlessSmsDeliveryInput):
        if ('SUPERTOKENS_ENV' in environ) and (environ['SUPERTOKENS_ENV'] == 'testing'):
            return
        sms_input_json = {
            'appName': app_info.app_name,
            'type': 'PASSWORDLESS_LOGIN',
            'phoneNumber': sms_input.phone_number,
            'userInputCode': sms_input.user_input_code,
            'urlWithLinkCode': sms_input.url_with_link_code,
            'codeLifetime': sms_input.code_life_time,
        }
        try:
            async with AsyncClient() as client:
                await client.post(  # type: ignore
                    SUPERTOKENS_SMS_SERVICE_URL,
                    json={
                        "smsInput": sms_input_json,
                    },
                    headers={'api-version': '0'}
                )
                # TODO: Handle 429 and undefined response?
                return
        except Exception:
            pass
        print("Free daily SMS quota reached. If using our managed service, please create a production environment to get dedicated API keys for SMS sending, or define your own method for sending SMS. For now, we are logging it below:")
        log_debug_message("SMS content: %s", json.dumps(sms_input_json))
    return func


class BackwardCompatibilityService(SMSDeliveryInterface[TypePasswordlessSmsDeliveryInput]):
    def __init__(self,
                 app_info: AppInfo,
                 create_and_send_custom_sms: Union[Callable[[TypePasswordlessSmsDeliveryInput], Awaitable[None]], None] = None
                 ) -> None:
        self.app_info = app_info
        self.create_and_send_custom_sms = default_create_and_send_custom_sms(self.app_info) if create_and_send_custom_sms is None else create_and_send_custom_sms

    async def send_sms(self, sms_input: TypePasswordlessSmsDeliveryInput) -> None:
        try:
            await self.create_and_send_custom_sms(sms_input)
        except Exception as _:
            pass
