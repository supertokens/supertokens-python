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

from typing import Any, Awaitable, Callable, Dict, Union

from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.interfaces import \
    TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailpassword.recipe import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.types import (
    TypeEmailPasswordPasswordResetEmailDeliveryInputUser, User)
from supertokens_python.recipe.emailpassword.utils import (
    InputEmailVerificationConfig, InputResetPasswordUsingTokenFeature,
    default_create_and_send_custom_email)
from supertokens_python.recipe.emailverification.emaildelivery.services.backwardCompatibility import \
    BackwardCompatibilityService as \
    EmailVerificationBackwardCompatibilityService
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.emailverification.types import \
    User as EmailVerificationUser
from supertokens_python.supertokens import AppInfo


class CreateAndSendCustomEmailInput:
    user: str
    email_verification_url_with_token: str
    user_context: Dict[str, Any]

class BackwardCompatibilityService(EmailDeliveryInterface[TypeEmailPasswordEmailDeliveryInput]):
    app_info: AppInfo
    emailVerificationBackwardCompatiblityService: EmailVerificationBackwardCompatibilityService

    def __init__(self,
                 app_info: AppInfo,
                 recipeInterfaceImpl: EmailPasswordRecipe, # Any,  # FIXME: Should be EmailPasswordRecipe. But leads to circular dependency
                #  create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]],
                 reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = None,
                 email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
                 ) -> None:
        self.app_info = app_info
        self.recipeInterfaceImpl = recipeInterfaceImpl
        self.reset_password_using_token_feature = reset_password_using_token_feature

        if reset_password_using_token_feature:
            if reset_password_using_token_feature.create_and_send_custom_email is None:
                reset_password_using_token_feature.create_and_send_custom_email = default_create_and_send_custom_email(self.app_info)
            self.reset_password_using_token_feature = reset_password_using_token_feature

        if email_verification_feature:
            if email_verification_feature.create_and_send_custom_email is not None:
                async def create_and_send_custom_email_wrapper(user: EmailVerificationUser, link: str, user_context: Dict[str, Any]):
                    user_info = await self.recipeInterfaceImpl.recipe_implementation.get_user_by_id(user.user_id, user_context)
                    if user_info is None:
                        raise Exception("Unknown User ID provided")

                    assert email_verification_feature.create_and_send_custom_email is not None
                    return await email_verification_feature.create_and_send_custom_email(user, link, user_context)


                email_verification_feature.create_and_send_custom_email = create_and_send_custom_email_wrapper
            self.email_verification_feature = email_verification_feature

        self.emailVerificationBackwardCompatiblityService = EmailVerificationBackwardCompatibilityService(
            app_info, create_and_send_custom_email=email_verification_feature.create_and_send_custom_email
        )

    async def send_email(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> Any:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            await self.emailVerificationBackwardCompatiblityService.send_email(email_input, user_context)
        else:
            user = await self.recipeInterfaceImpl.recipe_implementation.get_user_by_id(
                user_id=email_input.user.user_id,
                user_context=email_input.user_context
            )

            if user is None:
                raise Exception("Should never come here")

            assert self.reset_password_using_token_feature is not None
            assert self.reset_password_using_token_feature.create_and_send_custom_email is not None

            try:
                await self.reset_password_using_token_feature.create_and_send_custom_email(
                   user, email_input.password_reset_link, email_input.user_context
                )
            except Exception:
                pass
