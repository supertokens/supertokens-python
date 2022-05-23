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

from os import environ
from typing import Any, Awaitable, Callable, Dict, Union

from httpx import AsyncClient
from supertokens_python.ingredients.emaildelivery import EmailDeliveryInterface
from supertokens_python.recipe.passwordless.types import \
    TypePasswordlessEmailDeliveryInput
from supertokens_python.supertokens import AppInfo


def default_create_and_send_custom_email(app_info: AppInfo) -> Callable[[TypePasswordlessEmailDeliveryInput, Dict[str, Any]], Awaitable[None]]:
    async def func(email_input: TypePasswordlessEmailDeliveryInput, _: Dict[str, Any]):
        if ('SUPERTOKENS_ENV' in environ) and (environ['SUPERTOKENS_ENV'] == 'testing'):
            return
        try:
            data = {
                "email": email_input.email,
                "appName": app_info.app_name,
                "codeLifetime": email_input.code_life_time,
                "urlWithLinkCode": email_input.url_with_link_code,  # TODO: FIXME Must be valid (non-empty) url or we get error
                "userInputCode": email_input.user_input_code or "",  # TODO: FIXME
            }
            async with AsyncClient() as client:
                await client.post('https://api.supertokens.io/0/st/auth/passwordless/login', json=data, headers={'api-version': '0'})  # type: ignore
        except Exception:
            pass

    return func


class BackwardCompatibilityService(EmailDeliveryInterface[TypePasswordlessEmailDeliveryInput]):
    def __init__(self,
                 app_info: AppInfo,
                 create_and_send_custom_email: Union[
                     Callable[[TypePasswordlessEmailDeliveryInput, Dict[str, Any]], Awaitable[None]],
                     None
                 ] = None
                 ) -> None:
        self.app_info = app_info
        self.create_and_send_custom_email = create_and_send_custom_email if create_and_send_custom_email is not None else default_create_and_send_custom_email(app_info)

    async def send_email(self, email_input: TypePasswordlessEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        try:
            await self.create_and_send_custom_email(email_input, user_context)
        except Exception as _:
            pass
