import asyncio
from typing import List

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.session.asyncio import (
    get_all_session_handles_for_user,
    get_session_information,
)
from supertokens_python.recipe.session.interfaces import SessionInformationResult
from supertokens_python.types import APIResponse
from supertokens_python.utils import Awaitable

from ...interfaces import APIInterface, APIOptions, UserSessionsGetAPIResponse


async def handle_sessions_get(
    _api_interface: APIInterface, api_options: APIOptions
) -> APIResponse:
    user_id = api_options.request.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    response = await get_all_session_handles_for_user(user_id)

    sessions: List[SessionInformationResult] = []
    session_info_promises: List[Awaitable[None]] = []

    async def call_(i: int, session_handle: str):
        try:
            session_response = await get_session_information(session_handle)
            if session_response is not None:
                sessions[i] = session_response  # FIXME
        except Exception:
            pass

    for i, session_handle in enumerate(response):
        session_info_promises.append(call_(i, session_handle))

    asyncio.gather(*session_info_promises)  # TODO: Verify that this doesn't need await

    return UserSessionsGetAPIResponse(sessions)
