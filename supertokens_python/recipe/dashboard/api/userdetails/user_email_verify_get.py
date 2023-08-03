from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.emailverification.asyncio import is_email_verified
from ...interfaces import (
    APIInterface,
    APIOptions,
    UserEmailVerifyGetAPIResponse,
    FeatureNotEnabledError,
)

from typing import Union, Dict, Any


async def handle_user_email_verify_get(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[UserEmailVerifyGetAPIResponse, FeatureNotEnabledError]:
    req = api_options.request
    user_id = req.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    try:
        EmailVerificationRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledError()

    is_verified = await is_email_verified(user_id, user_context=user_context)
    return UserEmailVerifyGetAPIResponse(is_verified)
