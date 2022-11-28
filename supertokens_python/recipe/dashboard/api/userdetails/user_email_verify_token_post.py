from typing import Any, Dict, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailverification.asyncio import (
    create_email_verification_token,
    send_email,
)
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    CreateEmailVerificationTokenOkResult,
)
from supertokens_python.recipe.emailverification.recipe import (
    EmailVerificationRecipe,
    GetEmailForUserIdOkResult,
)
from supertokens_python.recipe.emailverification.types import (
    VerificationEmailTemplateVars,
    VerificationEmailTemplateVarsUser,
)
from supertokens_python.recipe.emailverification.utils import get_email_verify_link

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse,
    UserEmailVerifyTokenPostAPIOkResponse,
)


async def handle_email_verify_token_post(
    _api_interface: APIInterface, api_options: APIOptions
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

    email_response = await EmailVerificationRecipe.get_instance().get_email_for_user_id(
        user_id, {}
    )

    if not isinstance(email_response, GetEmailForUserIdOkResult):
        raise Exception("Should not come here")

    email_verification_token = await create_email_verification_token(user_id)

    if isinstance(
        email_verification_token, CreateEmailVerificationTokenEmailAlreadyVerifiedError
    ):
        return UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse()

    assert isinstance(email_verification_token, CreateEmailVerificationTokenOkResult)

    email_verify_link = get_email_verify_link(
        api_options.app_info, email_verification_token.token, user_id
    )

    await send_email(
        VerificationEmailTemplateVars(
            user=VerificationEmailTemplateVarsUser(user_id, email_response.email),
            email_verify_link=email_verify_link,
            user_context={},
        )
    )

    return UserEmailVerifyTokenPostAPIOkResponse()
