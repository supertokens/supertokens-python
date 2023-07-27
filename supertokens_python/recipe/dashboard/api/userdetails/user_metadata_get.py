from ...interfaces import (
    APIInterface,
    APIOptions,
    FeatureNotEnabledError,
    UserMetadataGetAPIOkResponse,
)
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.usermetadata.asyncio import get_user_metadata
from typing import Union, Dict, Any


async def handle_metadata_get(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[UserMetadataGetAPIOkResponse, FeatureNotEnabledError]:
    user_id = api_options.request.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    try:
        UserMetadataRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledError()

    metadata_response = await get_user_metadata(user_id, user_context=user_context)
    return UserMetadataGetAPIOkResponse(metadata_response.metadata)
