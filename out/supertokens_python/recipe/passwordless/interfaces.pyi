import abc
from .types import DeviceType as DeviceType, User as User
from .utils import PasswordlessConfig as PasswordlessConfig
from abc import ABC, abstractmethod
from supertokens_python.framework import BaseRequest as BaseRequest, BaseResponse as BaseResponse
from supertokens_python.recipe.session import SessionContainer as SessionContainer
from typing import Any, Dict, List, Union
from typing_extensions import Literal

class CreateCodeResult(ABC):
    status: Any
    pre_auth_session_id: Any
    code_id: Any
    device_id: Any
    user_input_code: Any
    link_code: Any
    code_life_time: Any
    time_created: Any
    def __init__(self, status: Literal['OK'], pre_auth_session_id: str, code_id: str, device_id: str, user_input_code: str, link_code: str, code_life_time: int, time_created: int) -> None: ...

class CreateCodeOkResult(CreateCodeResult):
    def __init__(self, pre_auth_session_id: str, code_id: str, device_id: str, user_input_code: str, link_code: str, code_life_time: int, time_created: int) -> None: ...

class CreateNewCodeForDeviceResult(ABC):
    status: Any
    pre_auth_session_id: Any
    code_id: Any
    device_id: Any
    user_input_code: Any
    link_code: Any
    code_life_time: Any
    time_created: Any
    is_ok: bool
    is_restart_flow_error: bool
    is_user_input_code_already_used_error: bool
    def __init__(self, status: Literal['OK', 'RESTART_FLOW_ERROR', 'USER_INPUT_CODE_ALREADY_USED_ERROR'], pre_auth_session_id: Union[str, None] = ..., code_id: Union[str, None] = ..., device_id: Union[str, None] = ..., user_input_code: Union[str, None] = ..., link_code: Union[str, None] = ..., code_life_time: Union[int, None] = ..., time_created: Union[int, None] = ...) -> None: ...

class CreateNewCodeForDeviceOkResult(CreateNewCodeForDeviceResult):
    is_ok: bool
    def __init__(self, pre_auth_session_id: str, code_id: str, device_id: str, user_input_code: str, link_code: str, code_life_time: int, time_created: int) -> None: ...

class CreateNewCodeForDeviceRestartFlowErrorResult(CreateNewCodeForDeviceResult):
    is_restart_flow_error: bool
    def __init__(self) -> None: ...

class CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult(CreateNewCodeForDeviceResult):
    is_user_input_code_already_used_error: bool
    def __init__(self) -> None: ...

class ConsumeCodeResult(ABC):
    status: Any
    created_new_user: Any
    user: Any
    failed_code_input_attempt_count: Any
    maximum_code_input_attempts: Any
    is_ok: bool
    is_incorrect_user_input_code_error: bool
    is_expired_user_input_code_error: bool
    is_restart_flow_error: bool
    def __init__(self, status: Literal['OK', 'INCORRECT_USER_INPUT_CODE_ERROR', 'EXPIRED_USER_INPUT_CODE_ERROR', 'RESTART_FLOW_ERROR'], created_new_user: Union[bool, None] = ..., user: Union[User, None] = ..., failed_code_input_attempt_count: Union[int, None] = ..., maximum_code_input_attempts: Union[int, None] = ...) -> None: ...

class ConsumeCodeOkResult(ConsumeCodeResult):
    is_ok: bool
    def __init__(self, created_new_user: bool, user: User) -> None: ...

class ConsumeCodeIncorrectUserInputCodeErrorResult(ConsumeCodeResult):
    is_incorrect_user_input_code_error: bool
    def __init__(self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int) -> None: ...

class ConsumeCodeExpiredUserInputCodeErrorResult(ConsumeCodeResult):
    is_expired_user_input_code_error: bool
    def __init__(self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int) -> None: ...

class ConsumeCodeRestartFlowErrorResult(ConsumeCodeResult):
    is_restart_flow_error: bool
    def __init__(self) -> None: ...

class UpdateUserResult(ABC):
    status: Any
    def __init__(self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR', 'EMAIL_ALREADY_EXISTS_ERROR', 'PHONE_NUMBER_ALREADY_EXISTS_ERROR']) -> None: ...

class UpdateUserOkResult(UpdateUserResult):
    def __init__(self) -> None: ...

class UpdateUserUnknownUserIdErrorResult(UpdateUserResult):
    def __init__(self) -> None: ...

class UpdateUserEmailAlreadyExistsErrorResult(UpdateUserResult):
    def __init__(self) -> None: ...

class UpdateUserPhoneNumberAlreadyExistsErrorResult(UpdateUserResult):
    def __init__(self) -> None: ...

class RevokeAllCodesResult(ABC):
    status: Any
    def __init__(self, status: Literal['OK']) -> None: ...

class RevokeAllCodesOkResult(RevokeAllCodesResult):
    def __init__(self) -> None: ...

class RevokeCodeResult(ABC):
    status: Any
    def __init__(self, status: Literal['OK']) -> None: ...

class RevokeCodeOkResult(RevokeCodeResult):
    def __init__(self) -> None: ...

class RecipeInterface(ABC, metaclass=abc.ABCMeta):
    def __init__(self) -> None: ...
    @abstractmethod
    async def create_code(self, email: Union[None, str], phone_number: Union[None, str], user_input_code: Union[None, str], user_context: Dict[str, Any]) -> CreateCodeResult: ...
    @abstractmethod
    async def create_new_code_for_device(self, device_id: str, user_input_code: Union[str, None], user_context: Dict[str, Any]) -> CreateNewCodeForDeviceResult: ...
    @abstractmethod
    async def consume_code(self, pre_auth_session_id: str, user_input_code: Union[str, None], device_id: Union[str, None], link_code: Union[str, None], user_context: Dict[str, Any]) -> ConsumeCodeResult: ...
    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]: ...
    @abstractmethod
    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]: ...
    @abstractmethod
    async def get_user_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> Union[User, None]: ...
    @abstractmethod
    async def update_user(self, user_id: str, email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> UpdateUserResult: ...
    @abstractmethod
    async def revoke_all_codes(self, email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> RevokeAllCodesResult: ...
    @abstractmethod
    async def revoke_code(self, code_id: str, user_context: Dict[str, Any]) -> RevokeCodeResult: ...
    @abstractmethod
    async def list_codes_by_email(self, email: str, user_context: Dict[str, Any]) -> List[DeviceType]: ...
    @abstractmethod
    async def list_codes_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> List[DeviceType]: ...
    @abstractmethod
    async def list_codes_by_device_id(self, device_id: str, user_context: Dict[str, Any]) -> Union[DeviceType, None]: ...
    @abstractmethod
    async def list_codes_by_pre_auth_session_id(self, pre_auth_session_id: str, user_context: Dict[str, Any]) -> Union[DeviceType, None]: ...

class APIOptions:
    request: Any
    response: Any
    recipe_id: Any
    config: Any
    recipe_implementation: Any
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str, config: PasswordlessConfig, recipe_implementation: RecipeInterface) -> None: ...

class CreateCodePostResponse(ABC, metaclass=abc.ABCMeta):
    status: Any
    device_id: Any
    pre_auth_session_id: Any
    flow_type: Any
    message: Any
    is_ok: bool
    is_general_error: bool
    def __init__(self, status: Literal['OK', 'GENERAL_ERROR'], device_id: Union[str, None] = ..., pre_auth_session_id: Union[str, None] = ..., flow_type: Union[None, Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']] = ..., message: Union[str, None] = ...) -> None: ...
    @abstractmethod
    def to_json(self) -> Dict[str, Any]: ...

class CreateCodePostOkResponse(CreateCodePostResponse):
    is_ok: bool
    def __init__(self, device_id: str, pre_auth_session_id: str, flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']) -> None: ...
    def to_json(self): ...

class CreateCodePostGeneralErrorResponse(CreateCodePostResponse):
    is_general_error: bool
    def __init__(self, message: str) -> None: ...
    def to_json(self): ...

class ResendCodePostResponse(ABC, metaclass=abc.ABCMeta):
    status: Any
    message: Any
    is_ok: bool
    is_general_error: bool
    is_restart_flow_error: bool
    def __init__(self, status: Literal['OK', 'GENERAL_ERROR', 'RESTART_FLOW_ERROR'], message: Union[str, None] = ...) -> None: ...
    @abstractmethod
    def to_json(self) -> Dict[str, Any]: ...

class ResendCodePostOkResponse(ResendCodePostResponse):
    is_ok: bool
    def __init__(self) -> None: ...
    def to_json(self): ...

class ResendCodePostRestartFlowErrorResponse(ResendCodePostResponse):
    is_restart_flow_error: bool
    def __init__(self) -> None: ...
    def to_json(self): ...

class ResendCodePostGeneralErrorResponse(ResendCodePostResponse):
    is_general_error: bool
    def __init__(self, message: str) -> None: ...
    def to_json(self): ...

class ConsumeCodePostResponse(ABC, metaclass=abc.ABCMeta):
    status: Any
    session: Any
    created_new_user: Any
    user: Any
    failed_code_input_attempt_count: Any
    maximum_code_input_attempts: Any
    message: Any
    is_ok: bool
    is_general_error: bool
    is_restart_flow_error: bool
    is_incorrect_user_input_code_error: bool
    is_expired_user_input_code_error: bool
    def __init__(self, status: Literal['OK', 'GENERAL_ERROR', 'RESTART_FLOW_ERROR', 'INCORRECT_USER_INPUT_CODE_ERROR', 'EXPIRED_USER_INPUT_CODE_ERROR'], created_new_user: Union[bool, None] = ..., user: Union[User, None] = ..., session: Union[SessionContainer, None] = ..., message: Union[str, None] = ..., failed_code_input_attempt_count: Union[int, None] = ..., maximum_code_input_attempts: Union[int, None] = ...) -> None: ...
    @abstractmethod
    def to_json(self) -> Dict[str, Any]: ...

class ConsumeCodePostOkResponse(ConsumeCodePostResponse):
    is_ok: bool
    def __init__(self, created_new_user: bool, user: User, session: SessionContainer) -> None: ...
    def to_json(self): ...

class ConsumeCodePostRestartFlowErrorResponse(ConsumeCodePostResponse):
    is_restart_flow_error: bool
    def __init__(self) -> None: ...
    def to_json(self): ...

class ConsumeCodePostGeneralErrorResponse(ConsumeCodePostResponse):
    is_general_error: bool
    def __init__(self, message: str) -> None: ...
    def to_json(self): ...

class ConsumeCodePostIncorrectUserInputCodeErrorResponse(ConsumeCodePostResponse):
    is_incorrect_user_input_code_error: bool
    def __init__(self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int) -> None: ...
    def to_json(self): ...

class ConsumeCodePostExpiredUserInputCodeErrorResponse(ConsumeCodePostResponse):
    is_expired_user_input_code_error: bool
    def __init__(self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int) -> None: ...
    def to_json(self): ...

class PhoneNumberExistsGetResponse(ABC):
    status: Any
    exists: Any
    def __init__(self, status: Literal['OK'], exists: bool) -> None: ...
    def to_json(self): ...

class PhoneNumberExistsGetOkResponse(PhoneNumberExistsGetResponse):
    def __init__(self, exists: bool) -> None: ...

class EmailExistsGetResponse(ABC):
    status: Any
    exists: Any
    def __init__(self, status: Literal['OK'], exists: bool) -> None: ...
    def to_json(self): ...

class EmailExistsGetOkResponse(EmailExistsGetResponse):
    def __init__(self, exists: bool) -> None: ...

class APIInterface(metaclass=abc.ABCMeta):
    disable_create_code_post: bool
    disable_resend_code_post: bool
    disable_consume_code_post: bool
    disable_email_exists_get: bool
    disable_phone_number_exists_get: bool
    def __init__(self) -> None: ...
    @abstractmethod
    async def create_code_post(self, email: Union[str, None], phone_number: Union[str, None], api_options: APIOptions, user_context: Dict[str, Any]) -> CreateCodePostResponse: ...
    @abstractmethod
    async def resend_code_post(self, device_id: str, pre_auth_session_id: str, api_options: APIOptions, user_context: Dict[str, Any]) -> ResendCodePostResponse: ...
    @abstractmethod
    async def consume_code_post(self, pre_auth_session_id: str, user_input_code: Union[str, None], device_id: Union[str, None], link_code: Union[str, None], api_options: APIOptions, user_context: Dict[str, Any]) -> ConsumeCodePostResponse: ...
    @abstractmethod
    async def email_exists_get(self, email: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse: ...
    @abstractmethod
    async def phone_number_exists_get(self, phone_number: str, api_options: APIOptions, user_context: Dict[str, Any]) -> PhoneNumberExistsGetResponse: ...
