from typing import Any, Dict, Union

from supertokens_python.asyncio import get_user
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.utils import (
    UserWithMetadata,
)
from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.usermetadata.asyncio import get_user_metadata

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserGetAPINoUserFoundError,
    UserGetAPIOkResponse,
)


async def handle_user_get(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    _user_context: Dict[str, Any],
) -> Union[
    UserGetAPINoUserFoundError,
    UserGetAPIOkResponse,
]:
    user_id = api_options.request.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    user_response = await get_user(user_id, _user_context)
    if user_response is None:
        return UserGetAPINoUserFoundError()

    user_with_metadata: UserWithMetadata = UserWithMetadata().from_user(user_response)

    try:
        UserMetadataRecipe.get_instance()
    except Exception:
        user_with_metadata.first_name = "FEATURE_NOT_ENABLED"
        user_with_metadata.last_name = "FEATURE_NOT_ENABLED"

        return UserGetAPIOkResponse(user_with_metadata)

    user_metadata = await get_user_metadata(user_id, user_context=_user_context)
    first_name = user_metadata.metadata.get("first_name", "")
    last_name = user_metadata.metadata.get("last_name", "")

    user_with_metadata.first_name = first_name
    user_with_metadata.last_name = last_name

    return UserGetAPIOkResponse(user_with_metadata)
