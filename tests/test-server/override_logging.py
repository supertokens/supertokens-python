import json
import time
from typing import Any, Callable, Coroutine, Dict, List, Set, Union

from httpx import Response
from supertokens_python.framework.flask.flask_request import FlaskRequest
from supertokens_python.recipe.accountlinking import RecipeLevelUser
from supertokens_python.recipe.accountlinking.interfaces import (
    CreatePrimaryUserOkResult,
    LinkAccountsOkResult,
)
from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.emailpassword.interfaces import (
    APIOptions as EmailPasswordAPIOptions,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    ConsumePasswordResetTokenOkResult,
    CreateResetPasswordOkResult,
    GeneratePasswordResetTokenPostOkResult,
    PasswordResetPostOkResult,
    SignUpOkResult,
    SignUpPostOkResult,
    UpdateEmailOrPasswordOkResult,
)
from supertokens_python.recipe.emailpassword.types import (
    FormField,
    PasswordResetEmailTemplateVars,
)
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    CreateEmailVerificationTokenOkResult,
    GetEmailForUserIdOkResult,
    VerifyEmailUsingTokenOkResult,
)
from supertokens_python.recipe.emailverification.recipe import IsVerifiedSCV
from supertokens_python.recipe.passwordless.interfaces import (
    APIOptions as PasswordlessAPIOptions,
)
from supertokens_python.recipe.session.claims import PrimitiveClaim
from supertokens_python.recipe.session.interfaces import (
    ClaimsValidationResult,
    RegenerateAccessTokenOkResult,
    SessionInformationResult,
)
from supertokens_python.recipe.session.session_class import Session
from supertokens_python.recipe.thirdparty.interfaces import (
    APIOptions as ThirdPartyAPIOptions,
)
from supertokens_python.recipe.thirdparty.provider import ProviderConfigForClient
from supertokens_python.recipe.thirdparty.types import UserInfo as TPUserInfo
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
    if isinstance(data, ProviderConfigForClient):
        return data.to_json()
    if isinstance(data, TPUserInfo):
        return data.to_json()
    if isinstance(data, GeneratePasswordResetTokenPostOkResult):
        return data.to_json()
    if isinstance(data, CreateEmailVerificationTokenOkResult):
        return {"token": data.token, "status": data.status}
    if isinstance(data, GetEmailForUserIdOkResult):
        return {"email": data.email, "status": "OK"}
    if isinstance(data, VerifyEmailUsingTokenOkResult):
        return {"status": data.status}
    if isinstance(data, CreateResetPasswordOkResult):
        return {"token": data.token, "status": "OK"}
    if isinstance(data, PasswordResetEmailTemplateVars):
        return data.to_json()
    if isinstance(data, ConsumePasswordResetTokenOkResult):
        return data.to_json()
    if isinstance(data, UpdateEmailOrPasswordOkResult):
        return {"status": "OK"}
    if isinstance(data, CreateEmailVerificationTokenEmailAlreadyVerifiedError):
        return {"status": "EMAIL_ALREADY_VERIFIED_ERROR"}
    if isinstance(data, PasswordResetPostOkResult):
        return {"status": "OK", "user": data.user.to_json(), "email": data.email}
    if isinstance(data, RecipeLevelUser):
        return data.to_json()
    if isinstance(data, RegenerateAccessTokenOkResult):
        return data.to_json()
    if isinstance(data, PrimitiveClaim):
        return "PrimitiveClaim"
    if isinstance(data, SessionInformationResult):
        return data.to_json()
    if isinstance(data, IsVerifiedSCV):
        return "IsVerifiedSCV"
    if is_jsonable(data):
        return data

    return "Some custom object"


def is_jsonable(x: Any) -> bool:
    try:
        json.dumps(x)
        return True
    except (TypeError, OverflowError):
        return False
