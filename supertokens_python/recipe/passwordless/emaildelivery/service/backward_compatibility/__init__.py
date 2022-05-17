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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Union

from supertokens_python.ingredients.emaildelivery import EmailDeliveryInterface
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.passwordless.interfaces import \
        TypePasswordlessEmailDeliveryInput


async def default_create_and_send_custom_email(
    _: TypePasswordlessEmailDeliveryInput,
    __: Dict[str, Any]
) -> None:
    # TODO
    pass


class BackwardCompatibilityService(EmailDeliveryInterface[TypePasswordlessEmailDeliveryInput]):
    def __init__(self,
                 app_info: AppInfo,
                 create_and_send_custom_email: Union[
                     Callable[[TypePasswordlessEmailDeliveryInput, Dict[str, Any]], Awaitable[None]],
                     None
                 ] = None
                 ) -> None:
        self.app_info = app_info
        self.create_and_send_custom_email = create_and_send_custom_email if create_and_send_custom_email is not None else default_create_and_send_custom_email

    async def send_email(self, email_input: TypePasswordlessEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        try:
            await self.create_and_send_custom_email(email_input, user_context)
        except Exception:
            pass
