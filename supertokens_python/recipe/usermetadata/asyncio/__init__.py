from typing import Any, Dict, Union

from supertokens_python.recipe.usermetadata.recipe import UserMetadataRecipe


async def get_user_metadata(
    user_id: str, user_context: Union[Dict[str, Any], None] = None
):
    if user_context is None:
        user_context = {}
    return (
        await UserMetadataRecipe.get_instance().recipe_implementation.get_user_metadata(
            user_id, user_context
        )
    )


async def update_user_metadata(
    user_id: str,
    metadata_update: Dict[str, Any],
    user_context: Union[Dict[str, Any], None] = None,
):
    if user_context is None:
        user_context = {}
    return await UserMetadataRecipe.get_instance().recipe_implementation.update_user_metadata(
        user_id, metadata_update, user_context
    )


async def clear_user_metadata(
    user_id: str, user_context: Union[Dict[str, Any], None] = None
):
    if user_context is None:
        user_context = {}
    return await UserMetadataRecipe.get_instance().recipe_implementation.clear_user_metadata(
        user_id, user_context
    )
