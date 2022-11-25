from typing import Any, Dict, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.session.asyncio import revoke_multiple_sessions
from ...interfaces import APIInterface, APIOptions, UserSessionsPostAPIResponse


async def handle_user_sessions_post(
    _api_interface: APIInterface, api_options: APIOptions
) -> UserSessionsPostAPIResponse:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    session_handles: Union[List[str], Any] = request_body.get("sessionHandles")

    if session_handles is None or not isinstance(session_handles, list):
        return raise_bad_input_exception(
            "Required parameter 'sessionHandles' is missing or has an invalid type"
        )

    await revoke_multiple_sessions(session_handles)
    return UserSessionsPostAPIResponse()
