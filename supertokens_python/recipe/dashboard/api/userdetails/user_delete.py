from ...interfaces import APIInterface, APIOptions, UserDeleteAPIResponse
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python import Supertokens


async def handle_user_delete(
    _api_interface: APIInterface, api_options: APIOptions
) -> UserDeleteAPIResponse:
    user_id = api_options.request.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    await Supertokens.get_instance().delete_user(user_id)

    return UserDeleteAPIResponse()
