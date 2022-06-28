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

from typing import TYPE_CHECKING, Any, Dict, Union, cast

from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService as EPBackwardCompatibilityService,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    RecipeInterface as EPRecipeInterface,
)
from supertokens_python.recipe.emailpassword.utils import (
    InputEmailVerificationConfig as EPInputEmailVerificationConfig,
)
from supertokens_python.recipe.emailpassword.utils import (
    InputResetPasswordUsingTokenFeature,
)
from supertokens_python.recipe.emailverification.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService as EVBackwardCompatibilityService,
)
from supertokens_python.recipe.emailverification.types import User as EVUser
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import RecipeInterface
from supertokens_python.recipe.thirdpartyemailpassword.types import (
    EmailTemplateVars,
    VerificationEmailTemplateVars,
)
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdpartyemailpassword.utils import (
        InputEmailVerificationConfig,
    )


class BackwardCompatibilityService(EmailDeliveryInterface[EmailTemplateVars]):
    ep_backward_compatiblity_service: EPBackwardCompatibilityService
    ev_backward_compatiblity_service: EVBackwardCompatibilityService

    def __init__(
        self,
        app_info: AppInfo,
        recipe_interface_impl: RecipeInterface,
        ep_recipe_interface_impl: EPRecipeInterface,
        reset_password_using_token_feature: Union[
            InputResetPasswordUsingTokenFeature, None
        ] = None,
        email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
    ) -> None:
        create_and_send_custom_email_wrapper = None
        input_create_and_send_custom_email = (
            email_verification_feature.create_and_send_custom_email
            if email_verification_feature is not None
            else None
        )

        if input_create_and_send_custom_email:

            async def create_and_send_custom_email_(
                user: EVUser, link: str, user_context: Dict[str, Any]
            ):
                user_info = await recipe_interface_impl.get_user_by_id(
                    user.user_id, user_context
                )
                if user_info is None:
                    raise Exception("Unknown User ID provided")

                return await input_create_and_send_custom_email(
                    user_info, link, user_context
                )

            create_and_send_custom_email_wrapper = create_and_send_custom_email_

        self.ev_backward_compatiblity_service = EVBackwardCompatibilityService(
            app_info, create_and_send_custom_email_wrapper
        )

        ep_email_verification_feature = cast(
            EPInputEmailVerificationConfig, email_verification_feature
        )
        self.ep_backward_compatiblity_service = EPBackwardCompatibilityService(
            app_info,
            ep_recipe_interface_impl,
            reset_password_using_token_feature,
            ep_email_verification_feature,
        )

    async def send_email(
        self, template_vars: EmailTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        if isinstance(template_vars, VerificationEmailTemplateVars):
            await self.ev_backward_compatiblity_service.send_email(
                template_vars, user_context
            )

        await self.ep_backward_compatiblity_service.send_email(
            template_vars, user_context
        )
