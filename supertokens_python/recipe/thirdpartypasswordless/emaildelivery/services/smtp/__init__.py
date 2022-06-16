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
    EmailDeliverySMTPConfig, Transporter)
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailverification.emaildelivery.services.smtp import \
    SMTPService as EmailVerificationSMTPService
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.passwordless.emaildelivery.services.smtp import \
    SMTPService as PlessSMTPService
from supertokens_python.recipe.passwordless.types import \
    TypePasswordlessEmailDeliveryInput
from supertokens_python.recipe.thirdpartypasswordless.types import \
    TypeThirdPartyPasswordlessEmailDeliveryInput

from .service_implementation import ServiceImplementation
from .service_implementation.email_verification_implementation import \
    ServiceImplementation as EmailVerificationServiceImpl
from .service_implementation.passwordless_implementation import \
    ServiceImplementation as PlessServiceImpl


class SMTPService(EmailDeliveryInterface[TypeThirdPartyPasswordlessEmailDeliveryInput]):

    def __init__(self, config: EmailDeliverySMTPConfig[TypeThirdPartyPasswordlessEmailDeliveryInput]) -> None:
        self.transporter = Transporter(config.smtp_settings)

        oi = ServiceImplementation(self.transporter)
        service_implementation = oi if config.override is None else config.override(oi)

        ev_config = EmailDeliverySMTPConfig[TypeEmailVerificationEmailDeliveryInput](
            smtp_settings=config.smtp_settings,
            override=lambda _: EmailVerificationServiceImpl(service_implementation)
        )
        self.ev_smtp_service = EmailVerificationSMTPService(ev_config)

        pless_config = EmailDeliverySMTPConfig[TypePasswordlessEmailDeliveryInput](
            smtp_settings=config.smtp_settings,
            override=lambda _: PlessServiceImpl(service_implementation)
        )
        self.pless_smtp_service = PlessSMTPService(pless_config)

    async def send_email(self, input_: TypeThirdPartyPasswordlessEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        if isinstance(input_, TypeEmailVerificationEmailDeliveryInput):
            return await self.ev_smtp_service.send_email(input_, user_context)

        return await self.pless_smtp_service.send_email(input_, user_context)
