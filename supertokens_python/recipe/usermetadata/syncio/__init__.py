from typing import Any, Dict

from supertokens_python.async_to_sync_wrapper import sync


async def get_user_metadata(user_id: str, user_context: Dict[str, Any]):
    from supertokens_python.recipe.usermetadata.asyncio import \
        get_user_metadata
    return sync(get_user_metadata(user_id, user_context))


async def update_user_metadata(user_id: str, metadata_update: Dict[str, Any], user_context: Dict[str, Any]):
    from supertokens_python.recipe.usermetadata.asyncio import \
        update_user_metadata
    return sync(update_user_metadata(user_id, metadata_update, user_context))


async def clear_user_metadata(user_id: str, user_context: Dict[str, Any]):
    from supertokens_python.recipe.usermetadata.asyncio import \
        clear_user_metadata
    return sync(clear_user_metadata(user_id, user_context))
