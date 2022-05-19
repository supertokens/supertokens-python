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
from supertokens_python.recipe.thirdpartyemailpassword.types import User

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Union, cast

from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.emaildelivery.service.backward_compatibility import \
    BackwardCompatibilityService as EmailPasswordBackwardCompatibilityService
from supertokens_python.recipe.emailpassword.interfaces import \
    TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailpassword.recipe_implementation import \
    RecipeImplementation as EPRecipeImplementation
from supertokens_python.recipe.emailpassword.types import User as EPUser
from supertokens_python.recipe.emailpassword.utils import \
    InputEmailVerificationConfig as EPInputEmailVerificationConfig
from supertokens_python.recipe.emailpassword.utils import \
    InputResetPasswordUsingTokenFeature
from supertokens_python.recipe.emailverification.emaildelivery.service.backward_compatibility import \
    BackwardCompatibilityService as \
    EmailVerificationBackwardCompatibilityService
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.emailverification.types import User as EVUser
from supertokens_python.recipe.thirdpartyemailpassword.recipeimplementation.implementation import \
    RecipeImplementation
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdpartyemailpassword.utils import \
        InputEmailVerificationConfig


# TODO: FIXME. This was copied from emailpassword backward_comp.

def default_create_and_send_custom_email(app_info: AppInfo) -> Callable[[EPUser, str, Dict[str, Any]], Awaitable[None]]:
    async def func(user: EPUser, password_reset_url_with_token: str, _: Dict[str, Any]):
        print(user, password_reset_url_with_token, _, app_info)

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
        inputCreateAndSendCustomEmail = email_verification_feature.create_and_send_custom_email if email_verification_feature is not None else None
        if inputCreateAndSendCustomEmail is None:
            ev_create_and_send_custom_email = None
        else:
            async def createAndSendCustomEmail(user: EVUser, link: str, user_context: Dict[str, Any]):
                user_info = await recipeInterfaceImpl.get_user_by_id(user.user_id, user_context)
                if user_info is None:
                    raise Exception("Unknown user ID provided")
                return await inputCreateAndSendCustomEmail(user_info, link, user_context)
            ev_create_and_send_custom_email = createAndSendCustomEmail

        self.ev_backward_comp_service = EmailVerificationBackwardCompatibilityService(
            app_info,
            ev_create_and_send_custom_email
        )
        ep_recipeInterfaceImpl = cast(EPRecipeImplementation, recipeInterfaceImpl)
        if email_verification_feature is not None:
            async def ep_get_email_verification_url(ep_user: EPUser, user_context: Dict[str, Any]):
                user = User(ep_user.user_id, ep_user.email, ep_user.time_joined)
                if email_verification_feature.get_email_verification_url is None:
                    return ""
                return await email_verification_feature.get_email_verification_url(user, user_context)

            async def ep_create_and_send_custom_email(ep_user: EPUser, link: str, user_context: Dict[str, Any]):
                user = User(ep_user.user_id, ep_user.email, ep_user.time_joined)
                if email_verification_feature.create_and_send_custom_email is None:
                    return
                await email_verification_feature.create_and_send_custom_email(user, link, user_context)

            ep_bc_email_verification_feature = EPInputEmailVerificationConfig(
                ep_get_email_verification_url,
                ep_create_and_send_custom_email
            )
        else:
            ep_bc_email_verification_feature = None
        self.ep_backward_comp_service = EmailPasswordBackwardCompatibilityService(
            app_info,
            ep_recipeInterfaceImpl,
            reset_password_using_token_feature,
            ep_bc_email_verification_feature,
        )

    async def send_email(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> Any:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            await self.emailVerificationBackwardCompatibilityService.send_email(email_input, user_context)
        else:
            await self.ep_backward_comp_service.send_email(email_input, user_context)
