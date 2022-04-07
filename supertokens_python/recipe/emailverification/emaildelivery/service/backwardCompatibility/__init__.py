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

from os import environ
from typing import Any, Awaitable, Callable, Dict, Union

from httpx import AsyncClient
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.emailverification.types import User
from supertokens_python.supertokens import AppInfo


def default_create_and_send_custom_email(app_info: AppInfo) -> Callable[[User, str, Dict[str, Any]], Awaitable[None]]:
    async def func(user: User, email_verification_url: str, _: Dict[str, Any]):
        if ('SUPERTOKENS_ENV' in environ) and (environ['SUPERTOKENS_ENV'] == 'testing'):
            return
        try:
            async with AsyncClient() as client:
                await client.post('https://api.supertokens.io/0/st/auth/email/verify', json={'email': user.email, 'appName': app_info.app_name, 'emailVerifyURL': email_verification_url}, headers={'api-version': '0'})  # type: ignore
        except Exception:
            pass
    return func

class BackwardCompatibilityService(EmailDeliveryInterface[TypeEmailVerificationEmailDeliveryInput]):
    def __init__(self,
                 app_info: AppInfo,
                 create_and_send_custom_email: Union[Callable[[User, str, Dict[str, Any]], Awaitable[None]], None] = None
                 ) -> None:
        self.app_info = app_info
        self.create_and_send_custom_email = default_create_and_send_custom_email(self.app_info) if create_and_send_custom_email is None else create_and_send_custom_email

    async def send_email(self, email_input: TypeEmailVerificationEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        try:
            email_user = User(email_input.user.id, email_input.user.email)
            await self.create_and_send_custom_email(email_user, email_input.email_verify_link, user_context)
        except Exception as _:
            pass
