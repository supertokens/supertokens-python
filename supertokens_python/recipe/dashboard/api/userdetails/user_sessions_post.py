from typing import Any, Dict, List, Optional

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.session.asyncio import revoke_multiple_sessions
from ...interfaces import APIInterface, APIOptions, UserSessionsPostAPIResponse


async def handle_user_sessions_post(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    _user_context: Dict[str, Any],
) -> UserSessionsPostAPIResponse:
    request_body = await api_options.request.json()  # type: ignore
    session_handles: Optional[List[str]] = request_body.get("sessionHandles")  # type: ignore

    if not isinstance(session_handles, list):
        raise_bad_input_exception(
            "Required parameter 'sessionHandles' is missing or has an invalid type"
        )

    await revoke_multiple_sessions(session_handles, _user_context)
    return UserSessionsPostAPIResponse()
