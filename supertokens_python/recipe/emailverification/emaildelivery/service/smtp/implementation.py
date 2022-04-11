

from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery.service.smtp import (
    GetContentResult, ServiceInterface, Transporter, TypeInputSendRawEmailFrom)
from supertokens_python.recipe.emailverification.emaildelivery.service.smtp.email_verify import \
    getEmailVerifyEmailContent
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput


class DefaultServiceImplementation(ServiceInterface[TypeEmailVerificationEmailDeliveryInput]):
    def __init__(self, transporter: Transporter) -> None:
        self.transporter = transporter

    async def send_raw_email(self, get_content_result: GetContentResult, config_from: TypeInputSendRawEmailFrom, user_context: Dict[str, Any]) -> None:
        self.transporter.send_email(config_from, get_content_result, user_context)

    def get_content(self, input: TypeEmailVerificationEmailDeliveryInput, user_context: Dict[str, Any]) -> GetContentResult:
        return getEmailVerifyEmailContent(input)


def getServiceImplementation(transporter: Transporter, input_send_raw_email_from: TypeInputSendRawEmailFrom) -> ServiceInterface[TypeEmailVerificationEmailDeliveryInput]:
    si = DefaultServiceImplementation(transporter)
    return si
