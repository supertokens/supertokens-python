from typing import Any, Dict, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailverification.asyncio import (
    send_email_verification_email,
    SendEmailVerificationEmailAlreadyVerifiedError,
)

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserEmailVerifyTokenPostAPIOkResponse,
    UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse,
)


async def handle_email_verify_token_post(
    _api_interface: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    UserEmailVerifyTokenPostAPIOkResponse,
    UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse,
]:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    user_id = request_body.get("userId")

    if user_id is None or not isinstance(user_id, str):
        raise_bad_input_exception(
            "Required parameter 'userId' is missing or has an invalid type"
        )

    res = await send_email_verification_email(
        tenant_id=tenant_id, user_id=user_id, email=None, user_context=user_context
    )

    if isinstance(res, SendEmailVerificationEmailAlreadyVerifiedError):
        return UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse()

    return UserEmailVerifyTokenPostAPIOkResponse()
