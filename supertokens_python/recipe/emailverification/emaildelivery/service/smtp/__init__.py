from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery.service.smtp import (
    EmailDeliverySMTPConfig, ServiceInterface, Transporter,
    getEmailServiceImplementation)
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailverification.recipe import \
    TypeEmailVerificationEmailDeliveryInput

from .implementation import getServiceImplementation


class SMTPService(EmailDeliveryInterface[TypeEmailVerificationEmailDeliveryInput]):
    serviceImpl: ServiceInterface[TypeEmailVerificationEmailDeliveryInput]

    def __init__(self, config: EmailDeliverySMTPConfig[TypeEmailVerificationEmailDeliveryInput]) -> None:
        self.config = config
        transporter = Transporter(config.smtpSettings)
        oi = getEmailServiceImplementation(config, getServiceImplementation)
        self.serviceImpl = oi if config.override is None else config.override(oi)

    async def send_email(self, email_input: TypeEmailVerificationEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        content = await self.serviceImpl.get_content(email_input)
        await self.serviceImpl.send_raw_email(content, email_input.user, user_context)
