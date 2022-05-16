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
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.interfaces import \
    TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailpassword.recipe_implementation import \
    RecipeImplementation
from supertokens_python.recipe.emailpassword.types import User
from supertokens_python.recipe.emailverification.emaildelivery.service.backward_compatibility import \
    BackwardCompatibilityService as \
    EmailVerificationBackwardCompatibilityService
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.emailverification.types import \
    User as EmailVerificationUser
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.utils import (
        InputEmailVerificationConfig, InputResetPasswordUsingTokenFeature)


def default_create_and_send_custom_email(
        app_info: AppInfo) -> Callable[[User, str, Dict[str, Any]], Awaitable[None]]:
    async def func(user: User, password_reset_url_with_token: str, _: Dict[str, Any]):
        if ('SUPERTOKENS_ENV' in environ) and (environ['SUPERTOKENS_ENV'] == 'testing'):
            return
        try:
            data = {
                'email': user.email,
                'appName': app_info.app_name,
                'passwordResetURL': password_reset_url_with_token
            }
            async with AsyncClient() as client:
                await client.post('https://api.supertokens.io/0/st/auth/password/reset', json=data, headers={'api-version': '0'})  # type: ignore
        except Exception:
            pass

    return func


class BackwardCompatibilityService(EmailDeliveryInterface[TypeEmailPasswordEmailDeliveryInput]):
    app_info: AppInfo
    emailVerificationBackwardCompatibilityService: EmailVerificationBackwardCompatibilityService

    def __init__(self,
                 app_info: AppInfo,
                 recipeInterfaceImpl: RecipeImplementation,
                 reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = None,
                 email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
                 ) -> None:
        self.app_info = app_info
        self.recipeInterfaceImpl = recipeInterfaceImpl

        reset_password_feature_send_email_func = default_create_and_send_custom_email(self.app_info)
        if reset_password_using_token_feature and reset_password_using_token_feature.create_and_send_custom_email is not None:
            reset_password_feature_send_email_func = reset_password_using_token_feature.create_and_send_custom_email

        self.reset_password_feature_send_email_func = reset_password_feature_send_email_func

        create_and_send_custom_email: Union[
            Callable[[EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]], None
        ] = None
        if email_verification_feature:
            if email_verification_feature.create_and_send_custom_email is not None:
                ev_create_and_send_custom_email = email_verification_feature.create_and_send_custom_email

                async def create_and_send_custom_email_wrapper(
                    user: EmailVerificationUser, link: str, user_context: Dict[str, Any]
                ):
                    user_info = await self.recipeInterfaceImpl.get_user_by_id(user.user_id, user_context)
                    if user_info is None:
                        raise Exception("Unknown User ID provided")

                    return await ev_create_and_send_custom_email(user_info, link, user_context)

                create_and_send_custom_email = create_and_send_custom_email_wrapper

            self.email_verification_feature = email_verification_feature

        self.emailVerificationBackwardCompatibilityService = EmailVerificationBackwardCompatibilityService(
            app_info, create_and_send_custom_email=create_and_send_custom_email
        )

    async def send_email(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> Any:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            await self.emailVerificationBackwardCompatibilityService.send_email(email_input, user_context)
        else:
            user = await self.recipeInterfaceImpl.get_user_by_id(
                user_id=email_input.user.user_id,
                user_context=user_context
            )

            if user is None:
                raise Exception("Should never come here")

            try:
                await self.reset_password_feature_send_email_func(
                    user, email_input.password_reset_link, user_context
                )
            except Exception:
                pass
