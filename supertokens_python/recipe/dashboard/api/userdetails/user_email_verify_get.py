from typing import Any, Dict, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.emailverification.asyncio import is_email_verified
from supertokens_python.types import RecipeUserId

from ...interfaces import (
    APIInterface,
    APIOptions,
    FeatureNotEnabledError,
    UserEmailVerifyGetAPIResponse,
)


async def handle_user_email_verify_get(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[UserEmailVerifyGetAPIResponse, FeatureNotEnabledError]:
    req = api_options.request
    recipe_user_id = req.get_query_param("recipeUserId")

    if recipe_user_id is None:
        raise_bad_input_exception("Missing required parameter 'recipeUserId'")

    try:
        EmailVerificationRecipe.get_instance_or_throw()
    except Exception:
        return FeatureNotEnabledError()

    is_verified = await is_email_verified(
        RecipeUserId(recipe_user_id), user_context=user_context
    )
    return UserEmailVerifyGetAPIResponse(is_verified)
