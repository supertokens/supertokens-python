

from typing import Any, Awaitable, Dict

from supertokens_python.ingredients.emaildelivery.service.smtp import (
    GetContentResult, ServiceInterface, Transporter, TypeInputSendRawEmailFrom)
from supertokens_python.recipe.emailpassword.emaildelivery.service.smtp.password_reset_implementation import \
    getPasswordResetEmailContent
from supertokens_python.recipe.emailpassword.types import \
    TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailverification.emaildelivery.service.smtp import \
    getServiceImplementation as \
    getEmailVerificationEmailDeliveryServiceImplementation
from supertokens_python.recipe.emailverification.emaildelivery.service.smtp.email_verify import \
    getEmailVerifyEmailContent
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput


class DefaultServiceImplementation(ServiceInterface[TypeEmailVerificationEmailDeliveryInput]):
    def __init__(self, transporter: Transporter, emailVerificationSeriveImpl: ServiceInterface[TypeEmailVerificationEmailDeliveryInput]) -> None:
        self.transporter = transporter
        self.emailVerificationSeriveImpl = emailVerificationSeriveImpl

    async def send_raw_email(self, get_content_result: GetContentResult, config_from: TypeInputSendRawEmailFrom, user_context: Dict[str, Any]) -> None:
        self.transporter.send_email(config_from, get_content_result, user_context)

    def get_content(self, input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> GetContentResult:
        if isinstance(input, TypeEmailVerificationEmailDeliveryInput):
            # return self.emailVerificationSeriveImpl.get_content # TODO
            pass
        return getPasswordResetEmailContent(input)


def getServiceImplementation(transporter: Transporter, input_send_raw_email_from: TypeInputSendRawEmailFrom) -> ServiceInterface[TypeEmailVerificationEmailDeliveryInput]:
    emailVerificationSeriveImpl = getEmailVerificationEmailDeliveryServiceImplementation(transporter, input_send_raw_email_from)
    si = DefaultServiceImplementation(transporter, emailVerificationSeriveImpl)
    return si
