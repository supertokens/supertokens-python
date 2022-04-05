
from typing import Any, Awaitable, Callable, Dict, Union

from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.emailverification.types import User
from supertokens_python.supertokens import AppInfo
from supertokens_python.recipe.emailverification.utils import default_create_and_send_custom_email


class CreateAndSendCustomEmailInput:
    user: str
    email_verification_url_with_token: str
    user_context: Dict[str, Any]


class BackwardCompatibilityService(EmailDeliveryInterface[TypeEmailVerificationEmailDeliveryInput]):
    def __init__(self,
                 app_info: AppInfo,
                 create_and_send_custom_email: Union[Callable[[User, str, Dict[str, Any]], Awaitable[None]], None] = None
                 ) -> None:
        self.app_info = app_info
        self.create_and_send_custom_email = default_create_and_send_custom_email(self.app_info) if create_and_send_custom_email is None else create_and_send_custom_email

    async def send_email(self, email_input: TypeEmailVerificationEmailDeliveryInput, user_context: Dict[str, Any]) -> None:
        try:
            await self.create_and_send_custom_email(email_input.user, email_input.email_verify_link, user_context)
        except Exception as _:
            pass
