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

from supertokens_python.ingredients.emaildelivery.services.smtp import (
    EmailDeliverySMTPConfig, ServiceInterface, Transporter)
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailverification.recipe import \
    TypeEmailVerificationEmailDeliveryInput

from .service_implementation import ServiceImplementation


class SMTPService(EmailDeliveryInterface[TypeEmailVerificationEmailDeliveryInput]):
    service_implementation: ServiceInterface[TypeEmailVerificationEmailDeliveryInput]

    def __init__(self, config: EmailDeliverySMTPConfig[TypeEmailVerificationEmailDeliveryInput]) -> None:
        transporter = Transporter(config.smtp_settings)
        oi = ServiceImplementation(transporter)
        self.service_implementation = oi if config.override is None else config.override(oi)

    async def send_email(self, input_: TypeEmailVerificationEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        content = await self.service_implementation.get_content(input_, user_context)
        await self.service_implementation.send_raw_email(content, user_context)
