from ...interfaces import SessionContainer as SessionContainer
from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest as FastApiRequest
from supertokens_python.recipe.session import SessionRecipe as SessionRecipe
from typing import Any, Dict, Union

def verify_session(anti_csrf_check: Union[bool, None] = ..., session_required: bool = ..., user_context: Union[None, Dict[str, Any]] = ...): ...
