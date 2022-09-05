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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Union

from httpx import AsyncClient
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryInterface
from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.emailpassword.interfaces import (
    EmailTemplateVars,
    RecipeInterface,
)
from supertokens_python.recipe.emailpassword.types import (
    User,
)
from supertokens_python.supertokens import AppInfo
from supertokens_python.utils import handle_httpx_client_exceptions

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.utils import (
        InputResetPasswordUsingTokenFeature,
    )


def default_create_and_send_custom_email(
    app_info: AppInfo,
) -> Callable[[User, str, Dict[str, Any]], Awaitable[None]]:
    async def func(user: User, password_reset_url_with_token: str, _: Dict[str, Any]):
        if ("SUPERTOKENS_ENV" in environ) and (environ["SUPERTOKENS_ENV"] == "testing"):
            return
        data = {
            "email": user.email,
            "appName": app_info.app_name,
            "passwordResetURL": password_reset_url_with_token,
        }
        try:
            async with AsyncClient() as client:
                resp = await client.post("https://api.supertokens.io/0/st/auth/password/reset", json=data, headers={"api-version": "0"})  # type: ignore
                resp.raise_for_status()
                log_debug_message("Password reset email sent to %s", user.email)
        except Exception as e:
            log_debug_message("Error sending password reset email")
            handle_httpx_client_exceptions(e, data)

    return func


class BackwardCompatibilityService(EmailDeliveryInterface[EmailTemplateVars]):
    app_info: AppInfo

    def __init__(
        self,
        app_info: AppInfo,
        recipe_interface_impl: RecipeInterface,
        reset_password_using_token_feature: Union[
            InputResetPasswordUsingTokenFeature, None
        ] = None,
    ) -> None:
        self.recipe_interface_impl = recipe_interface_impl

        reset_password_feature_send_email_func = default_create_and_send_custom_email(
            app_info
        )
        if (
            reset_password_using_token_feature
            and reset_password_using_token_feature.create_and_send_custom_email
            is not None
        ):
            reset_password_feature_send_email_func = (
                reset_password_using_token_feature.create_and_send_custom_email
            )

        self.reset_password_feature_send_email_func = (
            reset_password_feature_send_email_func
        )

    async def send_email(
        self, template_vars: EmailTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        user = await self.recipe_interface_impl.get_user_by_id(
            user_id=template_vars.user.id, user_context=user_context
        )
        if user is None:
            raise Exception("Should never come here")

        try:
            await self.reset_password_feature_send_email_func(
                user, template_vars.password_reset_link, user_context
            )
        except Exception:
            pass
