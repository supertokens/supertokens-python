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


from typing import Any, Dict

from httpx import AsyncClient
from supertokens_python.ingredients.smsdelivery.services.supertokens import (
    SUPERTOKENS_SMS_SERVICE_URL,
)
from supertokens_python.ingredients.smsdelivery.types import SMSDeliveryInterface
from supertokens_python.logger import log_debug_message
from supertokens_python.supertokens import Supertokens
from supertokens_python.utils import handle_httpx_client_exceptions

from ....types import PasswordlessLoginSMSTemplateVars


class SuperTokensSMSService(SMSDeliveryInterface[PasswordlessLoginSMSTemplateVars]):
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def send_sms(
        self,
        template_vars: PasswordlessLoginSMSTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        supertokens = Supertokens.get_instance()
        app_name = supertokens.app_info.app_name

        sms_input = {
            "type": "PASSWORDLESS_LOGIN",
            "phoneNumber": template_vars.phone_number,
            "codeLifetime": template_vars.code_life_time,
            "appName": app_name,
        }
        if template_vars.url_with_link_code:
            sms_input["urlWithLinkCode"] = template_vars.url_with_link_code
        if template_vars.user_input_code:
            sms_input["userInputCode"] = template_vars.user_input_code
        try:
            async with AsyncClient() as client:
                await client.post(  # type: ignore
                    SUPERTOKENS_SMS_SERVICE_URL,
                    json={
                        "apiKey": self.api_key,
                        "smsInput": sms_input,
                    },
                    headers={"api-version": "0"},
                )
        except Exception as e:
            log_debug_message("Error sending passwordless login SMS")
            handle_httpx_client_exceptions(e, sms_input)
            raise e
