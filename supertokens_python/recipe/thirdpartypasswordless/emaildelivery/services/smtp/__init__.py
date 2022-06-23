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
    Transporter)
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface, EmailDeliverySMTPConfig
from supertokens_python.recipe.emailverification.emaildelivery.services.smtp import \
    SMTPService as EmailVerificationSMTPService
from supertokens_python.recipe.emailverification.types import VerificationEmailTemplateVars
from supertokens_python.recipe.passwordless.emaildelivery.services.smtp import \
    SMTPService as PlessSMTPService
from supertokens_python.recipe.passwordless.types import \
    PasswordlessLoginEmailTemplateVars
from supertokens_python.recipe.thirdpartypasswordless.types import \
    ThirdPartyPasswordlessEmailTemplateVars

from .service_implementation import ServiceImplementation
from .service_implementation.email_verification_implementation import \
    ServiceImplementation as EmailVerificationServiceImpl
from .service_implementation.passwordless_implementation import \
    ServiceImplementation as PlessServiceImpl


class SMTPService(EmailDeliveryInterface[ThirdPartyPasswordlessEmailTemplateVars]):

    def __init__(self, config: EmailDeliverySMTPConfig[ThirdPartyPasswordlessEmailTemplateVars]) -> None:
        self.transporter = Transporter(config.smtp_settings)

        oi = ServiceImplementation(self.transporter)
        service_implementation = oi if config.override is None else config.override(oi)

        ev_config = EmailDeliverySMTPConfig[VerificationEmailTemplateVars](
            smtp_settings=config.smtp_settings,
            override=lambda _: EmailVerificationServiceImpl(service_implementation)
        )
        self.ev_smtp_service = EmailVerificationSMTPService(ev_config)

        pless_config = EmailDeliverySMTPConfig[PasswordlessLoginEmailTemplateVars](
            smtp_settings=config.smtp_settings,
            override=lambda _: PlessServiceImpl(service_implementation)
        )
        self.pless_smtp_service = PlessSMTPService(pless_config)

    async def send_email(self, template_vars: ThirdPartyPasswordlessEmailTemplateVars, user_context: Dict[str, Any]) -> None:
        if isinstance(template_vars, VerificationEmailTemplateVars):
            return await self.ev_smtp_service.send_email(template_vars, user_context)

        return await self.pless_smtp_service.send_email(template_vars, user_context)
