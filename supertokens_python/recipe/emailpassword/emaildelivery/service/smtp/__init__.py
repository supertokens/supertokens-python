from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery.service.smtp import (
    EmailDeliverySMTPConfig, ServiceInterface, SMTPServiceConfigFrom,
    Transporter)
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.types import \
    TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailverification.emaildelivery.service.smtp import \
    SMTPService as EmailVerificationSMTPService
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput

from .email_verification_implementation import \
    getServiceInterface as getEmailVerificationServiceImpl
from .implementation import getServiceImplementation


class SMTPService(EmailDeliveryInterface[TypeEmailPasswordEmailDeliveryInput]):
    serviceImpl: ServiceInterface[TypeEmailPasswordEmailDeliveryInput]

    def __init__(self, config: EmailDeliverySMTPConfig[TypeEmailPasswordEmailDeliveryInput]) -> None:
        self.config = config
        self.transporter = Transporter(config.smtpSettings)
        oi = getServiceImplementation(self.transporter)
        self.serviceImpl = oi if config.override is None else config.override(oi)

        ev_config = EmailDeliverySMTPConfig[TypeEmailVerificationEmailDeliveryInput](
            smtpSettings=config.smtpSettings,
            override=lambda _: getEmailVerificationServiceImpl(self.serviceImpl)
        )
        self.email_verification_smtp_service = EmailVerificationSMTPService(ev_config)

    async def send_email(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            return await self.email_verification_smtp_service.send_email(email_input, user_context)

        content = self.serviceImpl.get_content(email_input, user_context)
        send_raw_email_from = SMTPServiceConfigFrom(
            self.config.smtpSettings.email_from.name,
            self.config.smtpSettings.email_from.email
        )
        await self.serviceImpl.send_raw_email(content, send_raw_email_from, user_context)
