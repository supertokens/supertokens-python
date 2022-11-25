from supertokens_python.exceptions import raise_bad_input_exception

from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.usermetadata.asyncio import get_user_metadata
from supertokens_python.types import APIResponse

from supertokens_python.recipe.dashboard.utils import get_user_for_recipe_id

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserGetAPINoUserFoundError,
    UserGetAPIOkResponse,
)
from ...utils import is_valid_recipe_id


async def handle_user_get(
    _api_interface: APIInterface, api_options: APIOptions
) -> APIResponse:
    user_id = api_options.request.get_query_param("userId")
    recipe_id = api_options.request.get_query_param("recipeId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    if recipe_id is None:
        raise_bad_input_exception("Missing required parameter 'recipeId'")

    if not is_valid_recipe_id(recipe_id):
        raise_bad_input_exception("Invalid recipe id")

    user = (await get_user_for_recipe_id(user_id, recipe_id)).get("user")

    if user is None:
        return UserGetAPINoUserFoundError()

    # FIXME: Shouldn't be required, no?
    recipe_id_: str = recipe_id  # type: ignore
    user_id_: str = user_id  # type: ignore

    try:
        UserMetadataRecipe.get_instance()
    except Exception:
        user = {
            **user,
            "firstName": "FEATURE_NOT_ENABLED",
            "lastName": "FEATURE_NOT_ENABLED",
        }

        return UserGetAPIOkResponse(recipe_id_, user)

    user_metadata = await get_user_metadata(user_id_)
    first_name = user_metadata.metadata.get("first_name", "")
    last_name = user_metadata.metadata.get("last_name", "")

    user = {
        **user,
        "firstName": first_name,
        "lastName": last_name,
    }

    return UserGetAPIOkResponse(recipe_id_, user)
