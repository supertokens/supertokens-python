
from typing import Any, Awaitable, Callable, Dict, Union

from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryInterface
from supertokens_python.recipe.emailpassword.interfaces import \
    TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailpassword.types import User
from supertokens_python.recipe.emailpassword.utils import (
    InputEmailVerificationConfig, InputResetPasswordUsingTokenFeature,
    default_create_and_send_custom_email)
from supertokens_python.recipe.emailverification.emaildelivery.services.backwardCompatibility import \
    BackwardCompatibilityService as \
    EmailVerificationBackwardCompatibilityService
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.supertokens import AppInfo

# from supertokens_python.recipe.emailpassword.recipe import EmailPasswordRecipe


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
                 recipeInterfaceImpl: Any,  # FIXME: Should be EmailPasswordRecipe. But leads to circular dependency
                 create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]],
                 email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
                 reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = None,
                 ) -> None:
        self.app_info = app_info
        self.recipeInterfaceImpl = recipeInterfaceImpl
        self.reset_password_using_token_feature = reset_password_using_token_feature

        if create_and_send_custom_email is None:
            self.create_and_send_custom_email = default_create_and_send_custom_email(self.app_info)
        else:
            self.create_and_send_custom_email = create_and_send_custom_email

        self.emailVerificationBackwardCompatiblityService = EmailVerificationBackwardCompatibilityService(
            app_info, create_and_send_custom_email=self.create_and_send_custom_email
        )

    async def send_email(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> Any:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            await self.emailVerificationBackwardCompatiblityService.send_email(email_input, user_context)
        else:
            user = await self.recipeInterfaceImpl.get_user_by_id(
                user_id=email_input.user.user_id,
                user_context=email_input.user_context
            )

            if user is None:
                raise Exception("Should never come here")

            assert self.reset_password_using_token_feature is not None
            assert self.reset_password_using_token_feature.create_and_send_custom_email is not None

            try:
                await self.reset_password_using_token_feature.create_and_send_custom_email(
                    email_input.user, email_input.password_reset_link, email_input.user_context
                )
            except Exception:
                pass
