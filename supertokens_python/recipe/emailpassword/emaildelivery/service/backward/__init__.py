
from typing import Any, Awaitable, Callable, Dict, Union

from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.interfaces import TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailpassword.types import User
from supertokens_python.supertokens import AppInfo

from supertokens_python.recipe.emailverification.emaildelivery.services.backward import BackwardCompatibilityService as EmailVerificationBackwardCompatibilityService


class CreateAndSendCustomEmailInput:
    user: str
    email_verification_url_with_token: str
    user_context: Dict[str, Any]


# from supertokens_python.recipe.emailpassword.utils import default_create_and_send_custom_email


class BackwardCompatibilityService(EmailDeliveryInterface[TypeEmailPasswordEmailDeliveryInput]):
    app_info: AppInfo

    emailVerificationBackwardCompatiblityService: EmailVerificationBackwardCompatibilityService

    def __init__(self,
                 app_info: AppInfo,
                 #  create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]]
                 ) -> None:
        self.app_info = app_info
        # self.emailVerificationBackwardCompatiblityService =
        # self.create_and_send_custom_email = default_create_and_send_custom_email(self.app_info) if create_and_send_custom_email is None else create_and_send_custom_email

    async def send_email(self, email_input: Union[TypeEmailPasswordEmailDeliveryInput, None]) -> Any:
        if email_input is None:
            return

        if email_input.type == "EMAIL_VERIFICATION":
            await self.emailVerificationBackwardCompatiblityService.send_email(email_input=email_input)
        else:
            user = self.recipeInterfaceImpl.get_user_by_id(
                user_id=email_input.user.id,
                user_context=email_input.user_context
            )

            if user is None:
                raise Exception("Shouldn't have come here")

            try:
                await self.reset_password_using_token_feature.create_and_send_custom_email(
                    email_input.user, email_input.password_reset_link, email_input.user_context
                )
            except Exception as _:
                pass
