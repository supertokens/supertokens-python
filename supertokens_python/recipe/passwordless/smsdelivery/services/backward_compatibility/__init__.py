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
from typing import Any, Dict

from httpx import AsyncClient, HTTPStatusError, Response
from supertokens_python.ingredients.smsdelivery.services.supertokens import (
    SUPERTOKENS_SMS_SERVICE_URL,
)
from supertokens_python.ingredients.smsdelivery.types import SMSDeliveryInterface
from supertokens_python.logger import log_debug_message
from supertokens_python.supertokens import AppInfo
from supertokens_python.utils import handle_httpx_client_exceptions

from ....types import PasswordlessLoginSMSTemplateVars


async def create_and_send_sms_using_supertokens_service(
    app_info: AppInfo, input_: PasswordlessLoginSMSTemplateVars
):
    if ("SUPERTOKENS_ENV" in environ) and (environ["SUPERTOKENS_ENV"] == "testing"):
        return

    sms_input_json = {
        "appName": app_info.app_name,
        "type": "PASSWORDLESS_LOGIN",
        "phoneNumber": input_.phone_number,
        "codeLifetime": input_.code_life_time,
    }
    if input_.user_input_code:
        sms_input_json["userInputCode"] = input_.user_input_code
    if input_.url_with_link_code:
        sms_input_json["urlWithLinkCode"] = input_.url_with_link_code

    try:
        async with AsyncClient() as client:
            res = await client.post(  # type: ignore
                SUPERTOKENS_SMS_SERVICE_URL,
                json={
                    "smsInput": sms_input_json,
                },
                headers={"api-version": "0"},
            )
            res.raise_for_status()
            log_debug_message("Passwordless login SMS sent to %s", input_.phone_number)
            return
    except Exception as e:
        log_debug_message("Error sending passwordless login SMS")
        handle_httpx_client_exceptions(e)

        if isinstance(e, HTTPStatusError):  # type: ignore
            res: Response = e.response  # type: ignore
            if res.status_code != 429:  # type: ignore (429 == Too many requests)
                data = res.json()
                if "err" in data:
                    raise Exception(data["err"])
                if data:
                    raise Exception(json.dumps(data))
                if data is None:
                    raise e
            else:
                pass  # Reach Point (1)
        else:
            log_debug_message("Error: %s", str(e))
            raise e

    # Point (1): Reached only when we get HTTPStatusError with e.response.status_code == 429
    print(
        "Free daily SMS quota reached. If you want to use SuperTokens to send SMS, please sign up on supertokens.com to get your SMS API key, else you can also define your own method by overriding the service. For now, we are logging it below:"
    )
    print("SMS content:\n", json.dumps(input_.__dict__, indent=2))


class BackwardCompatibilityService(
    SMSDeliveryInterface[PasswordlessLoginSMSTemplateVars]
):
    def __init__(
        self,
        app_info: AppInfo,
    ) -> None:
        self.app_info = app_info

    async def send_sms(
        self,
        template_vars: PasswordlessLoginSMSTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        await create_and_send_sms_using_supertokens_service(
            self.app_info, template_vars
        )  # Note: intentionally not using try-except (unlike other recipes)
