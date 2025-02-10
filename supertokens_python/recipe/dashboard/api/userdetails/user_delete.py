from typing import Any, Dict

from supertokens_python.asyncio import delete_user
from supertokens_python.exceptions import raise_bad_input_exception

from ...interfaces import APIInterface, APIOptions, UserDeleteAPIResponse


async def handle_user_delete(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    _user_context: Dict[str, Any],
) -> UserDeleteAPIResponse:
    user_id = api_options.request.get_query_param("userId")
    remove_all_linked_accounts_query_value = api_options.request.get_query_param(
        "removeAllLinkedAccounts"
    )

    if remove_all_linked_accounts_query_value is not None:
        remove_all_linked_accounts_query_value = (
            remove_all_linked_accounts_query_value.strip().lower()
        )

    remove_all_linked_accounts = (
        True
        if remove_all_linked_accounts_query_value is None
        else remove_all_linked_accounts_query_value == "true"
    )

    if user_id is None or user_id == "":
        raise_bad_input_exception("Missing required parameter 'userId'")

    await delete_user(user_id, remove_all_linked_accounts)

    return UserDeleteAPIResponse()
