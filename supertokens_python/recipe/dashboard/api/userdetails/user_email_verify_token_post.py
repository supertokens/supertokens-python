from typing import Any, Dict, Union

from supertokens_python.asyncio import get_user
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailverification.asyncio import (
    SendEmailVerificationEmailAlreadyVerifiedError,
    send_email_verification_email,
)
from supertokens_python.types import RecipeUserId

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse,
    UserEmailVerifyTokenPostAPIOkResponse,
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
    recipe_user_id = request_body.get("recipeUserId")

    if recipe_user_id is None or not isinstance(recipe_user_id, str):
        raise_bad_input_exception(
            "Required parameter 'recipeUserId' is missing or has an invalid type"
        )

    user = await get_user(recipe_user_id, user_context)

    if user is None:
        raise_bad_input_exception("User not found")

    res = await send_email_verification_email(
        tenant_id=tenant_id,
        user_id=user.id,
        recipe_user_id=RecipeUserId(recipe_user_id),
        email=None,
        user_context=user_context,
    )

    if isinstance(res, SendEmailVerificationEmailAlreadyVerifiedError):
        return UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse()

    return UserEmailVerifyTokenPostAPIOkResponse()
