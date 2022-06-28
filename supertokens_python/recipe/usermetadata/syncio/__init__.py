from typing import Any, Dict, Union

from supertokens_python.async_to_sync_wrapper import sync


def get_user_metadata(user_id: str, user_context: Union[Dict[str, Any], None] = None):
    from supertokens_python.recipe.usermetadata.asyncio import get_user_metadata

    return sync(get_user_metadata(user_id, user_context))


def update_user_metadata(
    user_id: str,
    metadata_update: Dict[str, Any],
    user_context: Union[Dict[str, Any], None] = None,
):
    from supertokens_python.recipe.usermetadata.asyncio import update_user_metadata

    return sync(update_user_metadata(user_id, metadata_update, user_context))


def clear_user_metadata(user_id: str, user_context: Union[Dict[str, Any], None] = None):
    from supertokens_python.recipe.usermetadata.asyncio import clear_user_metadata

    return sync(clear_user_metadata(user_id, user_context))
