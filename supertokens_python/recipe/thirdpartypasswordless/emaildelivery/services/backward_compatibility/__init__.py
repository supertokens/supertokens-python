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
from supertokens_python.recipe.emailverification.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService as EVBackwardCompatibilityService,
)
from supertokens_python.recipe.emailverification.types import (
    VerificationEmailTemplateVars,
)
from supertokens_python.recipe.emailverification.types import User as EVUser
from supertokens_python.recipe.passwordless.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService as PlessBackwardCompatibilityService,
)
from supertokens_python.recipe.passwordless.types import (
    CreateAndSendCustomEmailParameters,
)
from supertokens_python.recipe.thirdpartypasswordless.interfaces import RecipeInterface
from supertokens_python.recipe.thirdpartypasswordless.types import EmailTemplateVars
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdpartypasswordless.utils import (
        InputEmailVerificationConfig,
    )


class BackwardCompatibilityService(EmailDeliveryInterface[EmailTemplateVars]):
    pless_backward_compatiblity_service: PlessBackwardCompatibilityService
    ev_backward_compatiblity_service: EVBackwardCompatibilityService

    def __init__(
        self,
        app_info: AppInfo,
        recipe_interface_impl: RecipeInterface,
        create_and_send_custom_email: Union[
            Callable[
                [CreateAndSendCustomEmailParameters, Dict[str, Any]], Awaitable[None]
            ],
            None,
        ] = None,
        ev_feature: Union[InputEmailVerificationConfig, None] = None,
    ) -> None:
        ev_create_and_send_custom_email = None
        if ev_feature:
            if ev_feature.create_and_send_custom_email is not None:
                original_create_and_send_custom_email = (
                    ev_feature.create_and_send_custom_email
                )

                async def create_and_send_custom_email_wrapper(
                    user: EVUser, link: str, user_context: Dict[str, Any]
                ):
                    user_info = await recipe_interface_impl.get_user_by_id(
                        user.user_id, user_context
                    )
                    if user_info is None:
                        raise Exception("Unknown User ID provided")

                    return await original_create_and_send_custom_email(
                        user_info, link, user_context
                    )

                ev_create_and_send_custom_email = create_and_send_custom_email_wrapper

        self.ev_backward_compatiblity_service = EVBackwardCompatibilityService(
            app_info, ev_create_and_send_custom_email
        )

        self.pless_backward_compatiblity_service = PlessBackwardCompatibilityService(
            app_info, create_and_send_custom_email
        )

    async def send_email(
        self, template_vars: EmailTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        if isinstance(template_vars, VerificationEmailTemplateVars):
            await self.ev_backward_compatiblity_service.send_email(
                template_vars, user_context
            )
        else:
            await self.pless_backward_compatiblity_service.send_email(
                template_vars, user_context
            )
