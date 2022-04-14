from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery.service.smtp import (
    EmailDeliverySMTPConfig, ServiceInterface, SMTPServiceConfigFrom,
    Transporter)
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailverification.recipe import \
    TypeEmailVerificationEmailDeliveryInput

from .implementation import ServiceImplementation


class SMTPService(EmailDeliveryInterface[TypeEmailVerificationEmailDeliveryInput]):
    serviceImpl: ServiceInterface[TypeEmailVerificationEmailDeliveryInput]

    def __init__(self, config: EmailDeliverySMTPConfig[TypeEmailVerificationEmailDeliveryInput]) -> None:
        self.config = config
        self.transporter = Transporter(config.smtpSettings)
        oi = ServiceImplementation(self.transporter)
        self.serviceImpl = oi if config.override is None else config.override(oi)

    async def send_email(self, email_input: TypeEmailVerificationEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        content = await self.serviceImpl.get_content(email_input, user_context)
        send_raw_email_from = SMTPServiceConfigFrom(
            self.config.smtpSettings.email_from.name,
            self.config.smtpSettings.email_from.email
        )
        await self.serviceImpl.send_raw_email(content, send_raw_email_from, user_context)
