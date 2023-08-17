from typing import Union, Dict, Any

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.utils import get_user_for_recipe_id
from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.usermetadata.asyncio import get_user_metadata

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserGetAPINoUserFoundError,
    UserGetAPIOkResponse,
    UserGetAPIRecipeNotInitialisedError,
)
from ...utils import is_recipe_initialised, is_valid_recipe_id


async def handle_user_get(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    _user_context: Dict[str, Any],
) -> Union[
    UserGetAPINoUserFoundError,
    UserGetAPIOkResponse,
    UserGetAPIRecipeNotInitialisedError,
]:
    user_id = api_options.request.get_query_param("userId")
    recipe_id = api_options.request.get_query_param("recipeId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    if recipe_id is None:
        raise_bad_input_exception("Missing required parameter 'recipeId'")

    if not is_valid_recipe_id(recipe_id):
        raise_bad_input_exception("Invalid recipe id")

    if not is_recipe_initialised(recipe_id):
        return UserGetAPIRecipeNotInitialisedError()

    user_response = await get_user_for_recipe_id(user_id, recipe_id)
    if user_response is None:
        return UserGetAPINoUserFoundError()

    user = user_response.user

    try:
        UserMetadataRecipe.get_instance()
    except Exception:
        user.first_name = "FEATURE_NOT_ENABLED"
        user.last_name = "FEATURE_NOT_ENABLED"

        return UserGetAPIOkResponse(recipe_id, user)

    user_metadata = await get_user_metadata(user_id, user_context=_user_context)
    first_name = user_metadata.metadata.get("first_name", "")
    last_name = user_metadata.metadata.get("last_name", "")

    user.first_name = first_name
    user.last_name = last_name

    return UserGetAPIOkResponse(recipe_id, user)
