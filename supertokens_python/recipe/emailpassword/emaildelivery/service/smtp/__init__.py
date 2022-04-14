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

from .service_implementation import ServiceImplementation
from .service_implementation.email_verification_implementation import \
    ServiceImplementation as EmailVerificationServiceImpl


class SMTPService(EmailDeliveryInterface[TypeEmailPasswordEmailDeliveryInput]):
    service_implementation: ServiceInterface[TypeEmailPasswordEmailDeliveryInput]

    def __init__(self, config: EmailDeliverySMTPConfig[TypeEmailPasswordEmailDeliveryInput]) -> None:
        self.config = config
        self.transporter = Transporter(config.smtpSettings)
        oi = ServiceImplementation(self.transporter)
        self.service_implementation = oi if config.override is None else config.override(oi)

        ev_config = EmailDeliverySMTPConfig[TypeEmailVerificationEmailDeliveryInput](
            smtpSettings=config.smtpSettings,
            override=lambda _: EmailVerificationServiceImpl(self.service_implementation)
        )
        self.email_verification_smtp_service = EmailVerificationSMTPService(ev_config)

    async def send_email(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            return await self.email_verification_smtp_service.send_email(email_input, user_context)

        content = await self.service_implementation.get_content(email_input, user_context)
        send_raw_email_from = SMTPServiceConfigFrom(
            self.config.smtpSettings.email_from.name,
            self.config.smtpSettings.email_from.email
        )
        await self.service_implementation.send_raw_email(content, send_raw_email_from, user_context)
