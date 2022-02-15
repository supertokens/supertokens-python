from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from .types import User as User
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Awaitable, Callable, Dict, Union

def default_get_email_verification_url(app_info: AppInfo) -> Callable[[User, Dict[str, Any]], Awaitable[str]]: ...
def default_create_and_send_custom_email(app_info: AppInfo) -> Callable[[User, str, Dict[str, Any]], Awaitable[None]]: ...

class OverrideConfig:
    functions: Any
    apis: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ...) -> None: ...

class ParentRecipeEmailVerificationConfig:
    override: Any
    get_email_verification_url: Any
    create_and_send_custom_email: Any
    get_email_for_user_id: Any
    def __init__(self, get_email_for_user_id: Callable[[str, Dict[str, Any]], Awaitable[str]], override: Union[OverrideConfig, None] = ..., get_email_verification_url: Union[Callable[[User, Dict[str, Any]], Awaitable[str]], None] = ..., create_and_send_custom_email: Union[Callable[[User, str, Dict[str, Any]], Awaitable[None]], None] = ...) -> None: ...

class EmailVerificationConfig:
    get_email_for_user_id: Any
    get_email_verification_url: Any
    create_and_send_custom_email: Any
    override: Any
    def __init__(self, override: OverrideConfig, get_email_verification_url: Callable[[User, Dict[str, Any]], Awaitable[str]], create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]], get_email_for_user_id: Callable[[str, Dict[str, Any]], Awaitable[str]]) -> None: ...

def validate_and_normalise_user_input(app_info: AppInfo, config: ParentRecipeEmailVerificationConfig): ...
