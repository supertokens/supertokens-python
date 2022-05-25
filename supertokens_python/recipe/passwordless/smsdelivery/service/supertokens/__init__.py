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


from httpx import AsyncClient
from supertokens_python.ingredients.smsdelivery.service.supertokens import (
    SUPERTOKENS_SMS_SERVICE_URL, SupertokensServiceConfig)
from supertokens_python.ingredients.smsdelivery.types import \
    SMSDeliveryInterface
from supertokens_python.supertokens import Supertokens

from ....types import TypePasswordlessSmsDeliveryInput


class SuperTokensService(SMSDeliveryInterface[TypePasswordlessSmsDeliveryInput]):
    def __init__(self,
                 config: SupertokensServiceConfig
                 ) -> None:
        self.config = config

    async def send_sms(self, sms_input: TypePasswordlessSmsDeliveryInput) -> None:
        supertokens = Supertokens.get_instance()
        app_name = supertokens.app_info.app_name

        try:
            async with AsyncClient() as client:
                await client.post(  # type: ignore
                    SUPERTOKENS_SMS_SERVICE_URL,
                    json={
                        "apiKey": self.config.api_key,
                        "smsInput": {
                            'type': 'PASSWORDLESS_LOGIN',
                            'phoneNumber': sms_input.phone_number,
                            'userInputCode': sms_input.user_input_code,
                            'urlWithLinkCode': sms_input.url_with_link_code,
                            'codeLifetime': sms_input.code_life_time,
                            'appName': app_name,
                        },
                    },
                    headers={'api-version': '0'}
                )
        except Exception:
            pass
