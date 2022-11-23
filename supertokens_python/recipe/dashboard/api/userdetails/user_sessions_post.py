from typing import Any, Dict, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.session.asyncio import revoke_multiple_sessions
from supertokens_python.types import APIResponse

from ...interfaces import APIInterface, APIOptions, APIResponse


class UserSessionsPostAPIResponse(APIResponse):
    # TODO: Move to interfaces.py
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


async def handle_user_sessions_post(
    _api_interface: APIInterface, api_options: APIOptions
) -> APIResponse:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    session_handles: Union[List[str], Any] = request_body.get("sessionHandles")

    if session_handles is None or not isinstance(session_handles, list):
        return raise_bad_input_exception(
            "Required parameter 'sessionHandles' is missing or has an invalid type"
        )

    await revoke_multiple_sessions(session_handles)
    return UserSessionsPostAPIResponse()
