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

from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery.services.smtp import \
    EmailDeliverySMTPConfig
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailverification.emaildelivery.services.smtp import \
    SMTPService as EmailVerificationSMTPService
from supertokens_python.recipe.thirdparty.types import \
    TypeThirdPartyEmailDeliveryInput


class SMTPService(EmailDeliveryInterface[TypeThirdPartyEmailDeliveryInput]):
    ev_smtp_service: EmailVerificationSMTPService

    def __init__(self, config: EmailDeliverySMTPConfig[TypeThirdPartyEmailDeliveryInput]) -> None:
        self.ev_smtp_service = EmailVerificationSMTPService(config)

    async def send_email(self, input_: TypeThirdPartyEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        await self.ev_smtp_service.send_email(input_, user_context)
