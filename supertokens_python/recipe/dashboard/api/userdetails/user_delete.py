from typing import Any, Dict

from ...interfaces import APIInterface, APIOptions, UserDeleteAPIResponse
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python import Supertokens


async def handle_user_delete(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    _user_context: Dict[str, Any],
) -> UserDeleteAPIResponse:
    user_id = api_options.request.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    await Supertokens.get_instance().delete_user(user_id, _user_context)

    return UserDeleteAPIResponse()
