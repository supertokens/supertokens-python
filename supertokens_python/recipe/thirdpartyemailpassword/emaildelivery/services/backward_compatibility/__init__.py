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

from typing import TYPE_CHECKING, Any, Dict, Union

from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.emaildelivery.service.backward_compatibility import \
    BackwardCompatibilityService as EmailPasswordBackwardCompatibilityService
from supertokens_python.recipe.emailpassword.interfaces import \
    TypeEmailPasswordEmailDeliveryInput
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
from supertokens_python.recipe.thirdpartyemailpassword.types import (
    TypeThirdPartyEmailPasswordEmailDeliveryInput, User)
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdpartyemailpassword.utils import \
        InputEmailVerificationConfig


class BackwardCompatibilityService(EmailDeliveryInterface[TypeThirdPartyEmailPasswordEmailDeliveryInput]):
    app_info: AppInfo
    ep_backward_compatiblity_service: EPBackwardCompatibilityService

    def __init__(self,
                 app_info: AppInfo,
                 recipe_interface_impl: RecipeImplementation,
                 reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = None,
                 email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
                 ) -> None:
        self.recipe_interface_impl = recipe_interface_impl

        ep_bc_email_verification_feature = None
        if email_verification_feature is not None and email_verification_feature.create_and_send_custom_email is not None:
            # TODO: Shouldn't it be `user: EVUser`??
            async def create_and_send_custom_email_wrapper(user: EPUser, link: str, user_context: Dict[str, Any]):
                user_info = await recipe_interface_impl.get_user_by_id(user.user_id, user_context)
                if user_info is None:
                    raise Exception("Unknown User ID provided")

                assert email_verification_feature.create_and_send_custom_email
                # TODO: WHY IS THE CODE NOT WORKING WITHOUT THIS ASSERT?? (UNEXPECTED BEHAVIOUR)

                return await email_verification_feature.create_and_send_custom_email(user_info, link, user_context)

            ep_bc_email_verification_feature = EPInputEmailVerificationConfig(
                None,  # TODO: Is this okay? (Most likely no) But the node PR isn't passing get_email_verification_url
                create_and_send_custom_email_wrapper
            )

        self.ep_backward_compatiblity_service = EPBackwardCompatibilityService(
            app_info,
            ep_recipe_interface_impl,
            reset_password_using_token_feature,
            ep_bc_email_verification_feature,
        )

    async def send_email(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> Any:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            await self.ev_backward_comp_service.send_email(email_input, user_context)
        else:
            await self.ep_backward_comp_service.send_email(email_input, user_context)
