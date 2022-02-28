from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union

from supertokens_python.recipe.thirdparty import \
    interfaces as ThirdPartyInterfaces
from supertokens_python.recipe.thirdparty.interfaces import (
    AuthorisationUrlGetResponse, SignInUpPostResponse, SignInUpResult)
from supertokens_python.recipe.thirdparty.provider import Provider
from typing_extensions import Literal

from ..passwordless import interfaces as PlessInterfaces
from ..passwordless.interfaces import (CreateCodePostResponse,
                                       CreateCodeResult,
                                       CreateNewCodeForDeviceResult,
                                       DeviceType, EmailExistsGetResponse,
                                       PhoneNumberExistsGetResponse,
                                       ResendCodePostResponse,
                                       RevokeAllCodesResult, RevokeCodeResult,
                                       UpdateUserResult)
from ..session import SessionContainer
from .types import User

ThirdPartyAPIOptions = ThirdPartyInterfaces.APIOptions
PasswordlessAPIOptions = PlessInterfaces.APIOptions


class ConsumeCodeResult(ABC):
    def __init__(self,
                 status: Literal['OK',
                                 'INCORRECT_USER_INPUT_CODE_ERROR',
                                 'EXPIRED_USER_INPUT_CODE_ERROR',
                                 'RESTART_FLOW_ERROR'],
                 created_new_user: Union[bool, None] = None,
                 user: Union[User, None] = None,
                 failed_code_input_attempt_count: Union[int, None] = None,
                 maximum_code_input_attempts: Union[int, None] = None
                 ):
        self.status: Literal['OK',
                             'INCORRECT_USER_INPUT_CODE_ERROR',
                             'EXPIRED_USER_INPUT_CODE_ERROR',
                             'RESTART_FLOW_ERROR'] = status
        self.created_new_user: Union[bool, None] = created_new_user
        self.user: Union[User, None] = user
        self.failed_code_input_attempt_count: Union[int, None] = failed_code_input_attempt_count
        self.maximum_code_input_attempts: Union[int, None] = maximum_code_input_attempts
        self.is_ok: bool = False
        self.is_incorrect_user_input_code_error: bool = False
        self.is_expired_user_input_code_error: bool = False
        self.is_restart_flow_error: bool = False


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_users_by_email(self, email: str, user_context: Dict[str, Any]) -> List[User]:
        pass

    @abstractmethod
    async def get_user_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(self, third_party_id: str,
                                          third_party_user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def thirdparty_sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                                    email_verified: bool, user_context: Dict[str, Any]) -> SignInUpResult:
        pass

    @abstractmethod
    async def create_code(self,
                          email: Union[None, str],
                          phone_number: Union[None, str],
                          user_input_code: Union[None, str],
                          user_context: Dict[str, Any]) -> CreateCodeResult:
        pass

    @abstractmethod
    async def create_new_code_for_device(self,
                                         device_id: str,
                                         user_input_code: Union[str, None],
                                         user_context: Dict[str, Any]) -> CreateNewCodeForDeviceResult:
        pass

    @abstractmethod
    async def consume_code(self,
                           pre_auth_session_id: str,
                           user_input_code: Union[str, None],
                           device_id: Union[str, None],
                           link_code: Union[str, None],
                           user_context: Dict[str, Any]) -> ConsumeCodeResult:
        pass

    @abstractmethod
    async def update_passwordless_user(self, user_id: str,
                                       email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> UpdateUserResult:
        pass

    @abstractmethod
    async def revoke_all_codes(self,
                               email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> RevokeAllCodesResult:
        pass

    @abstractmethod
    async def revoke_code(self, code_id: str, user_context: Dict[str, Any]) -> RevokeCodeResult:
        pass

    @abstractmethod
    async def list_codes_by_email(self, email: str, user_context: Dict[str, Any]) -> List[DeviceType]:
        pass

    @abstractmethod
    async def list_codes_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> List[DeviceType]:
        pass

    @abstractmethod
    async def list_codes_by_device_id(self, device_id: str, user_context: Dict[str, Any]) -> Union[DeviceType, None]:
        pass

    @abstractmethod
    async def list_codes_by_pre_auth_session_id(self, pre_auth_session_id: str,
                                                user_context: Dict[str, Any]) -> Union[DeviceType, None]:
        pass


class ConsumeCodePostResponse(ABC):
    def __init__(
        self,
        status: Literal[
            'OK',
            'GENERAL_ERROR',
            'RESTART_FLOW_ERROR',
            'INCORRECT_USER_INPUT_CODE_ERROR',
            'EXPIRED_USER_INPUT_CODE_ERROR'
        ],
        created_new_user: Union[bool, None] = None,
        user: Union[User, None] = None,
        session: Union[SessionContainer, None] = None,
        message: Union[str, None] = None,
        failed_code_input_attempt_count: Union[int, None] = None,
        maximum_code_input_attempts: Union[int, None] = None
    ):
        self.status: Literal[
            'OK',
            'GENERAL_ERROR',
            'RESTART_FLOW_ERROR',
            'INCORRECT_USER_INPUT_CODE_ERROR',
            'EXPIRED_USER_INPUT_CODE_ERROR'
        ] = status
        self.session: Union[SessionContainer, None] = session
        self.created_new_user: Union[bool, None] = created_new_user
        self.user: Union[User, None] = user
        self.failed_code_input_attempt_count: Union[int, None] = failed_code_input_attempt_count
        self.maximum_code_input_attempts: Union[int, None] = maximum_code_input_attempts
        self.message: Union[str, None] = message
        self.is_ok: bool = False
        self.is_general_error: bool = False
        self.is_restart_flow_error: bool = False
        self.is_incorrect_user_input_code_error: bool = False
        self.is_expired_user_input_code_error: bool = False


class APIInterface(ABC):
    def __init__(self):
        self.disable_thirdparty_sign_in_up_post = False
        self.disable_authorisation_url_get = False
        self.disable_apple_redirect_handler_post = False
        self.disable_create_code_post = False
        self.disable_resend_code_post = False
        self.disable_consume_code_post = False
        self.disable_passwordless_user_email_exists_get = False
        self.disable_passwordless_user_phone_number_exists_get = False

    @abstractmethod
    async def authorisation_url_get(self, provider: Provider,
                                    api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse:
        pass

    @abstractmethod
    async def thirdparty_sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None],
                                         api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> SignInUpPostResponse:
        pass

    @abstractmethod
    async def apple_redirect_handler_post(self, code: str, state: str,
                                          api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]):
        pass

    @abstractmethod
    async def create_code_post(self,
                               email: Union[str, None],
                               phone_number: Union[str, None],
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> CreateCodePostResponse:
        pass

    @abstractmethod
    async def resend_code_post(self,
                               device_id: str,
                               pre_auth_session_id: str,
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> ResendCodePostResponse:
        pass

    @abstractmethod
    async def consume_code_post(self,
                                pre_auth_session_id: str,
                                user_input_code: Union[str, None],
                                device_id: Union[str, None],
                                link_code: Union[str, None],
                                api_options: PasswordlessAPIOptions,
                                user_context: Dict[str, Any]) -> ConsumeCodePostResponse:
        pass

    @abstractmethod
    async def passwordless_user_email_exists_get(self,
                                                 email: str,
                                                 api_options: PasswordlessAPIOptions,
                                                 user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        pass

    @abstractmethod
    async def passwordless_user_phone_number_exists_get(self,
                                                        phone_number: str,
                                                        api_options: PasswordlessAPIOptions,
                                                        user_context: Dict[str, Any]) -> PhoneNumberExistsGetResponse:
        pass
