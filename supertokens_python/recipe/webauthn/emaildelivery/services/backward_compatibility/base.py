import os

from httpx import AsyncClient

from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryInterface
from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnEmailDeliveryInput,
    WebauthnRecoverAccountEmailDeliveryUser,
)
from supertokens_python.supertokens import AppInfo
from supertokens_python.types.base import UserContext
from supertokens_python.utils import handle_httpx_client_exceptions


async def create_and_send_email_using_supertokens_service(
    app_info: AppInfo,
    user: WebauthnRecoverAccountEmailDeliveryUser,
    recover_account_link: str,
):
    if os.environ.get("SUPERTOKENS_ENV") == "testing":
        return

    data = {
        "email": user.email,
        "appName": app_info.app_name,
        "recoverAccountURL": recover_account_link,
    }

    try:
        async with AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.supertokens.com/0/st/auth/webauthn/recover",
                json=data,
                headers={
                    "api-version": "0",
                    "content-type": "application/json; charset=utf-8",
                },
            )
            resp.raise_for_status()
            log_debug_message(f"Email sent to {user.email}")
    except Exception as e:
        log_debug_message("Error sending webauthn recover account email")
        handle_httpx_client_exceptions(e, data)


class BackwardCompatibilityService(
    EmailDeliveryInterface[TypeWebauthnEmailDeliveryInput]
):
    _app_info: AppInfo

    def __init__(self, app_info: AppInfo):
        self._app_info = app_info

    async def send_email(
        self, template_vars: TypeWebauthnEmailDeliveryInput, user_context: UserContext
    ):
        # we add this here cause the user may have overridden the sendEmail function
        # to change the input email and if we don't do this, the input email
        # will get reset by the getUserById call above.
        try:
            await create_and_send_email_using_supertokens_service(
                app_info=self._app_info,
                user=template_vars.user,
                recover_account_link=template_vars.recover_account_link,
            )
        except Exception:
            pass
