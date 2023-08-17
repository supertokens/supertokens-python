import asyncio
from typing import List, Optional, Dict, Any

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.session.asyncio import (
    get_all_session_handles_for_user,
    get_session_information,
)

from ...interfaces import (
    APIInterface,
    APIOptions,
    SessionInfo,
    UserSessionsGetAPIResponse,
)


async def handle_sessions_get(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> UserSessionsGetAPIResponse:
    user_id = api_options.request.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception("Missing required parameter 'userId'")

    # Passing tenant id as None sets fetch_across_all_tenants to True
    # which is what we want here.
    session_handles = await get_all_session_handles_for_user(
        user_id, None, user_context
    )
    sessions: List[Optional[SessionInfo]] = [None for _ in session_handles]

    async def call_(i: int, session_handle: str):
        try:
            session_response = await get_session_information(
                session_handle, user_context
            )
            if session_response is not None:
                sessions[i] = SessionInfo(session_response)
        except Exception:
            sessions[i] = None

    session_info_promises = [
        call_(i, handle) for i, handle in enumerate(session_handles)
    ]

    await asyncio.gather(*session_info_promises)

    return UserSessionsGetAPIResponse([s for s in sessions if s is not None])
