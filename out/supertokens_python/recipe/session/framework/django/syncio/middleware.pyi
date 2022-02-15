from supertokens_python import Supertokens as Supertokens
from supertokens_python.async_to_sync_wrapper import sync as sync
from supertokens_python.exceptions import SuperTokensError as SuperTokensError
from supertokens_python.framework.django.django_request import DjangoRequest as DjangoRequest
from supertokens_python.framework.django.django_response import DjangoResponse as DjangoResponse
from supertokens_python.recipe.session import SessionRecipe as SessionRecipe
from typing import Any, Dict, Union

def verify_session(anti_csrf_check: Union[bool, None] = ..., session_required: bool = ..., user_context: Union[None, Dict[str, Any]] = ...): ...
