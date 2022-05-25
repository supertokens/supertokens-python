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

from typing import Awaitable, Callable, Union

from supertokens_python.ingredients.smsdelivery.types import \
    SMSDeliveryInterface
from supertokens_python.recipe.passwordless.smsdelivery.service.backward_compatibility import \
    BackwardCompatibilityService as PlessBackwardCompatibilityService
from supertokens_python.recipe.passwordless.types import \
    TypePasswordlessSmsDeliveryInput
from supertokens_python.supertokens import AppInfo

from ....types import TypeThirdPartyPasswordlessSmsDeliveryInput


class BackwardCompatibilityService(SMSDeliveryInterface[TypeThirdPartyPasswordlessSmsDeliveryInput]):
    pless_backward_compatibility_service: PlessBackwardCompatibilityService

    def __init__(self, app_info: AppInfo,
                 pless_create_and_send_custom_text_message: Union[Callable[[TypePasswordlessSmsDeliveryInput], Awaitable[None]], None] = None
                 ) -> None:
        self.app_info = app_info
        self.pless_backward_compatibility_service = PlessBackwardCompatibilityService(
            app_info, pless_create_and_send_custom_text_message
        )

    async def send_sms(self, sms_input: TypeThirdPartyPasswordlessSmsDeliveryInput) -> None:
        await self.pless_backward_compatibility_service.send_sms(sms_input)
