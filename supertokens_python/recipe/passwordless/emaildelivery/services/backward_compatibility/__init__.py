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

import json
from os import environ
from typing import Any, Dict

from httpx import AsyncClient, HTTPStatusError
from supertokens_python.ingredients.emaildelivery import EmailDeliveryInterface
from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginEmailTemplateVars,
)
from supertokens_python.supertokens import AppInfo
from supertokens_python.utils import handle_httpx_client_exceptions


async def create_and_send_email_with_supertokens_service(
    app_info: AppInfo, input_: PasswordlessLoginEmailTemplateVars
) -> None:
    if ("SUPERTOKENS_ENV" in environ) and (environ["SUPERTOKENS_ENV"] == "testing"):
        return

    data = {
        "email": input_.email,
        "appName": app_info.app_name,
        "codeLifetime": input_.code_life_time,
    }
    if input_.url_with_link_code:
        data["urlWithLinkCode"] = input_.url_with_link_code
    if input_.user_input_code:
        data["userInputCode"] = input_.user_input_code

    try:
        async with AsyncClient() as client:
            resp = await client.post("https://api.supertokens.io/0/st/auth/passwordless/login", json=data, headers={"api-version": "0"})  # type: ignore
            resp.raise_for_status()
            log_debug_message("Passwordless login email sent to %s", input_.email)
    except Exception as e:
        log_debug_message("Error sending passwordless login email")
        handle_httpx_client_exceptions(e, data)
        # If the error is thrown from the API:
        if isinstance(e, HTTPStatusError):
            body: Dict[str, Any] = e.response.json()  # type: ignore
            if body.get("err"):
                msg = body["err"]
            else:
                msg = json.dumps(body)

            raise Exception(msg)

        raise e


class BackwardCompatibilityService(
    EmailDeliveryInterface[PasswordlessLoginEmailTemplateVars]
):
    def __init__(
        self,
        app_info: AppInfo,
    ) -> None:
        self.app_info = app_info

    async def send_email(
        self,
        template_vars: PasswordlessLoginEmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        await create_and_send_email_with_supertokens_service(
            self.app_info, template_vars
        )  # Note: intentionally not using try-except (unlike other recipes)
