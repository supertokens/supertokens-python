from typing import Any, Callable, Coroutine, Dict, List, Set, Union
import time

from httpx import Response

from supertokens_python.framework.flask.flask_request import FlaskRequest
from supertokens_python.recipe.accountlinking.interfaces import (
    CreatePrimaryUserOkResult,
    LinkAccountsOkResult,
)
from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.emailpassword.interfaces import (
    APIOptions as EmailPasswordAPIOptions,
    SignUpOkResult,
    SignUpPostOkResult,
)
from supertokens_python.recipe.session.interfaces import ClaimsValidationResult
from supertokens_python.recipe.session.session_class import Session
from supertokens_python.recipe.thirdparty.interfaces import (
    APIOptions as ThirdPartyAPIOptions,
)
from supertokens_python.recipe.passwordless.interfaces import (
    APIOptions as PasswordlessAPIOptions,
)
from supertokens_python.types import AccountInfo, RecipeUserId, User

override_logs: List[Dict[str, Any]] = []


def reset_override_logs():
    global override_logs
    override_logs = []


def get_override_logs():
    return override_logs


def log_override_event(name: str, log_type: str, data: Any):
    override_logs.append(
        {
            "t": int(time.time() * 1000),
            "type": log_type,
            "name": name,
            "data": transform_logged_data(data),
        }
    )


def transform_logged_data(data: Any, visited: Union[Set[Any], None] = None) -> Any:
    if isinstance(data, dict):
        return {k: transform_logged_data(v, visited) for k, v in data.items()}  # type: ignore
    if isinstance(data, list):
        return [transform_logged_data(v, visited) for v in data]  # type: ignore
    if isinstance(data, tuple):
        return tuple(transform_logged_data(v, visited) for v in data)  # type: ignore

    if isinstance(data, FlaskRequest):
        return "FlaskRequest"
    if isinstance(data, Response):
        return "Response"
    if isinstance(data, RecipeUserId):
        return data.get_as_string()
    if isinstance(data, AccountInfoWithRecipeId):
        return data.to_json()
    if isinstance(data, AccountInfo):
        return data.to_json()
    if isinstance(data, User):
        return data.to_json()
    if isinstance(data, Coroutine):
        return "Coroutine"
    if isinstance(data, Callable):
        return "Callable"
    if isinstance(data, FormField):
        return data.to_json()
    if isinstance(data, EmailPasswordAPIOptions):
        return "EmailPasswordAPIOptions"
    if isinstance(data, ThirdPartyAPIOptions):
        return "ThirdPartyAPIOptions"
    if isinstance(data, PasswordlessAPIOptions):
        return "PasswordlessAPIOptions"
    if isinstance(data, SignUpOkResult):
        return data.to_json()
    if isinstance(data, CreatePrimaryUserOkResult):
        return data.to_json()
    if isinstance(data, LinkAccountsOkResult):
        return data.to_json()
    if isinstance(data, Session):
        from session import convert_session_to_json

        return convert_session_to_json(data)
    if isinstance(data, SignUpPostOkResult):
        return data.to_json()
    if isinstance(data, ClaimsValidationResult):
        return data.to_json()
    return data
