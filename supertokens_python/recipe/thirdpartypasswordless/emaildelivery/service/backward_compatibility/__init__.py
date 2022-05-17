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

from supertokens_python.ingredients.emaildelivery import EmailDeliveryInterface
from supertokens_python.recipe.emailverification.emaildelivery.service.backward_compatibility import \
    BackwardCompatibilityService as EVBackwardCompatibilityService
from supertokens_python.recipe.emailverification.types import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.passwordless.emaildelivery.service.backward_compatibility import \
    BackwardCompatibilityService as PlessBackwardCompatibilityService
from supertokens_python.recipe.passwordless.types import \
    TypePasswordlessEmailDeliveryInput
from supertokens_python.recipe.thirdpartypasswordless.recipeimplementation.implementation import \
    RecipeImplementation
from supertokens_python.recipe.thirdpartypasswordless.types import \
    TypeThirdPartyPasswordlessEmailDeliveryInput
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdpartypasswordless.utils import (
        InputEmailVerificationConfig, InputPasswordlessConfig)


async def default_create_and_send_custom_email(
    _: TypeThirdPartyPasswordlessEmailDeliveryInput,
    __: Dict[str, Any]
) -> None:
    # TODO
    pass


class BackwardCompatibilityService(EmailDeliveryInterface[TypeThirdPartyPasswordlessEmailDeliveryInput]):
    app_info: AppInfo
    pless_backward_compatiblity_service: PlessBackwardCompatibilityService
    ev_backward_compatiblity_service: EVBackwardCompatibilityService

    def __init__(self,
                 app_info: AppInfo,
                 recipeInterfaceImpl: RecipeImplementation,
                 ev_feature: Union[InputEmailVerificationConfig, None] = None,
                 pless_feature: Union[InputPasswordlessConfig, None] = None,
                 ) -> None:
        self.app_info = app_info
        self.recipeInterfaceImpl = recipeInterfaceImpl

        _ = ev_feature.create_and_send_custom_email if ev_feature is not None else None
        # if input_create_and_send_custom_email is None:
        #     create_and_send_custom_email = None
        # else:
        #     create_and_send_custom_email = default_create_and_send_custom_email

        self.ev_backward_compatiblity_service = EVBackwardCompatibilityService(
            app_info,
            None  # create_and_send_custom_email
        )

        self.pless_backward_compatiblity_service = PlessBackwardCompatibilityService(
            app_info,
            pless_feature.create_and_send_custom_email if pless_feature is not None else None
        )

    async def send_email(self, email_input: TypeThirdPartyPasswordlessEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            await self.ev_backward_compatiblity_service.send_email(email_input, user_context)
        elif isinstance(email_input, TypePasswordlessEmailDeliveryInput):
            await self.pless_backward_compatiblity_service.send_email(email_input, user_context)
