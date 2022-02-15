from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from abc import ABC
from supertokens_python import AppInfo as AppInfo
from typing import Any, Awaitable, Callable, Dict, Union
from typing_extensions import Literal

async def default_validate_phone_number(value: str): ...
def default_get_link_domain_and_path(app_info: AppInfo): ...
async def default_validate_email(value: str): ...
async def default_create_and_send_custom_text_message(_: CreateAndSendCustomTextMessageParameters, __: Dict[str, Any]) -> None: ...
async def default_create_and_send_custom_email(_: CreateAndSendCustomEmailParameters, __: Dict[str, Any]) -> None: ...

class CreateAndSendCustomEmailParameters:
    email: Any
    code_life_time: Any
    pre_auth_session_id: Any
    user_input_code: Any
    url_with_link_code: Any
    def __init__(self, code_life_time: int, pre_auth_session_id: str, email: str, user_input_code: Union[str, None] = ..., url_with_link_code: Union[str, None] = ...) -> None: ...

class CreateAndSendCustomTextMessageParameters:
    phone_number: Any
    code_life_time: Any
    pre_auth_session_id: Any
    user_input_code: Any
    url_with_link_code: Any
    def __init__(self, code_life_time: int, pre_auth_session_id: str, phone_number: str, user_input_code: Union[str, None] = ..., url_with_link_code: Union[str, None] = ...) -> None: ...

class OverrideConfig:
    functions: Any
    apis: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ...) -> None: ...

class ContactConfig(ABC):
    contact_method: Any
    def __init__(self, contact_method: Literal['PHONE', 'EMAIL', 'EMAIL_OR_PHONE']) -> None: ...

class ContactPhoneOnlyConfig(ContactConfig):
    create_and_send_custom_text_message: Any
    validate_phone_number: Any
    def __init__(self, create_and_send_custom_text_message: Callable[[CreateAndSendCustomTextMessageParameters, Dict[str, Any]], Awaitable[None]], validate_phone_number: Union[Callable[[str], Awaitable[Union[str, None]]], None] = ...) -> None: ...

class ContactEmailOnlyConfig(ContactConfig):
    create_and_send_custom_email: Any
    validate_email_address: Any
    def __init__(self, create_and_send_custom_email: Callable[[CreateAndSendCustomEmailParameters, Dict[str, Any]], Awaitable[None]], validate_email_address: Union[Callable[[str], Awaitable[Union[str, None]]], None] = ...) -> None: ...

class ContactEmailOrPhoneConfig(ContactConfig):
    create_and_send_custom_email: Any
    validate_email_address: Any
    create_and_send_custom_text_message: Any
    validate_phone_number: Any
    def __init__(self, create_and_send_custom_email: Callable[[CreateAndSendCustomEmailParameters, Dict[str, Any]], Awaitable[None]], create_and_send_custom_text_message: Callable[[CreateAndSendCustomTextMessageParameters, Dict[str, Any]], Awaitable[None]], validate_email_address: Union[Callable[[str], Awaitable[Union[str, None]]], None] = ..., validate_phone_number: Union[Callable[[str], Awaitable[Union[str, None]]], None] = ...) -> None: ...

class PhoneOrEmailInput:
    phone_number: Any
    email: Any
    def __init__(self, phone_number: Union[str, None], email: Union[str, None]) -> None: ...

class PasswordlessConfig:
    contact_config: Any
    override: Any
    flow_type: Any
    get_custom_user_input_code: Any
    get_link_domain_and_path: Any
    def __init__(self, contact_config: ContactConfig, override: OverrideConfig, flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'], get_link_domain_and_path: Callable[[PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = ...) -> None: ...

def validate_and_normalise_user_input(app_info: AppInfo, contact_config: ContactConfig, flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'], override: Union[OverrideConfig, None] = ..., get_link_domain_and_path: Union[Callable[[PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None] = ..., get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = ...): ...
