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

from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryInterface
from supertokens_python.recipe.emailverification.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService as EVBackwardCompatibilityService,
)
from supertokens_python.recipe.emailverification.types import User
from supertokens_python.recipe.thirdparty.interfaces import RecipeInterface
from supertokens_python.recipe.thirdparty.types import EmailTemplateVars
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.utils import InputEmailVerificationConfig


class BackwardCompatibilityService(EmailDeliveryInterface[EmailTemplateVars]):
    def __init__(
        self,
        app_info: AppInfo,
        recipe_interface_impl: RecipeInterface,
        email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
    ) -> None:
        input_create_and_send_custom_email = (
            email_verification_feature.create_and_send_custom_email
            if email_verification_feature is not None
            else None
        )
        if input_create_and_send_custom_email is None:
            email_verification_feature_config = None
        else:

            async def create_and_send_custom_email(
                user: User, link: str, user_context: Dict[str, Any]
            ):
                user_info = await recipe_interface_impl.get_user_by_id(
                    user_id=user.user_id, user_context=user_context
                )
                if user_info is None:
                    raise Exception("Unknown User ID provided")
                return await input_create_and_send_custom_email(
                    user_info, link, user_context
                )

            email_verification_feature_config = create_and_send_custom_email

        self.ev_backward_compatibility_service = EVBackwardCompatibilityService(
            app_info, email_verification_feature_config
        )

    async def send_email(
        self, template_vars: EmailTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        await self.ev_backward_compatibility_service.send_email(
            template_vars, user_context
        )
