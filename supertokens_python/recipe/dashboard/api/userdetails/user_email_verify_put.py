from typing import Any, Dict

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailverification.asyncio import (
    create_email_verification_token,
    unverify_email,
    verify_email_using_token,
)
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    VerifyEmailUsingTokenInvalidTokenError,
)

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserEmailVerifyPutAPIResponse,
)


async def handle_user_email_verify_put(
    _api_interface: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> UserEmailVerifyPutAPIResponse:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    user_id = request_body.get("userId")
    verified = request_body.get("verified")

    if user_id is None or not isinstance(user_id, str):
        raise_bad_input_exception(
            "Required parameter 'userId' is missing or has an invalid type"
        )

    if verified is None or not isinstance(verified, bool):
        raise_bad_input_exception(
            "Required parameter 'verified' is missing or has an invalid type"
        )

    if verified:
        token_response = await create_email_verification_token(
            tenant_id=tenant_id, user_id=user_id, email=None, user_context=user_context
        )

        if isinstance(
            token_response, CreateEmailVerificationTokenEmailAlreadyVerifiedError
        ):
            return UserEmailVerifyPutAPIResponse()

        verify_response = await verify_email_using_token(
            tenant_id=tenant_id, token=token_response.token, user_context=user_context
        )

        if isinstance(verify_response, VerifyEmailUsingTokenInvalidTokenError):
            # This should never happen because we consume the token immediately after creating it
            raise Exception("Should not come here")

    else:
        await unverify_email(user_id, user_context=user_context)

    return UserEmailVerifyPutAPIResponse()
