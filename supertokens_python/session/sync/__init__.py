from typing import Union, List

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.session import Session


def create_new_session(request, user_id: str, jwt_payload: Union[dict, None] = None,
                       session_data: Union[dict, None] = None):
    from supertokens_python.session import create_new_session
    return sync(create_new_session(request, user_id, jwt_payload, session_data))


def get_session(request, anti_csrf_check: Union[bool, None] = None, session_required: bool = True) -> Union[
    Session, None]:
    from supertokens_python.session import get_session
    return sync(get_session(request, anti_csrf_check, session_required))


def refresh_session(request) -> Session:
    from supertokens_python.session import refresh_session
    return sync(refresh_session(request))


def revoke_session(session_handle: str) -> bool:
    from supertokens_python.session import revoke_session
    return sync(revoke_session(session_handle))


def revoke_all_sessions_for_user(user_id: str) -> List[str]:
    from supertokens_python.session import revoke_all_sessions_for_user
    return sync(revoke_all_sessions_for_user(user_id))


def revoke_multiple_sessions(session_handles: List[str]) -> List[str]:
    from supertokens_python.session import revoke_multiple_sessions
    return sync(revoke_multiple_sessions(session_handles))


def get_session_data(session_handle: str) -> dict:
    from supertokens_python.session import get_session_data
    return sync(get_session_data(session_handle))


def update_session_data(session_handle: str, new_session_data: dict) -> None:
    from supertokens_python.session import update_session_data
    return sync(update_session_data(session_handle, new_session_data))


def get_jwt_payload(session_handle: str) -> dict:
    from supertokens_python.session import get_jwt_payload
    return sync(get_jwt_payload(session_handle))


async def update_jwt_payload(session_handle: str, new_jwt_payload: dict) -> None:
    from supertokens_python.session import update_jwt_payload
    return sync(update_jwt_payload(session_handle, new_jwt_payload))
