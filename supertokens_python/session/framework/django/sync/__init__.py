from typing import Union

from supertokens_python.session import SessionRecipe
from supertokens_python.session.framework.django.sync.middleware import verify_session as original_verify_session


def verify_session(anti_csrf_check: Union[bool, None] = None, session_required: bool = True):
    return original_verify_session(SessionRecipe.get_instance(), anti_csrf_check, session_required)
