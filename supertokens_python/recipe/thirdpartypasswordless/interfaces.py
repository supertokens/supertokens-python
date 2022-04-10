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
    """ConsumeCodeResult.
    """

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
        """__init__.

        Parameters
        ----------
        status : Literal['OK',
                                         'INCORRECT_USER_INPUT_CODE_ERROR',
                                         'EXPIRED_USER_INPUT_CODE_ERROR',
                                         'RESTART_FLOW_ERROR']
            status
        created_new_user : Union[bool, None]
            created_new_user
        user : Union[User, None]
            user
        failed_code_input_attempt_count : Union[int, None]
            failed_code_input_attempt_count
        maximum_code_input_attempts : Union[int, None]
            maximum_code_input_attempts
        """
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


class ConsumeCodeOkResult(ConsumeCodeResult):
    """ConsumeCodeOkResult.
    """

    def __init__(self, created_new_user: bool, user: User):
        """__init__.

        Parameters
        ----------
        created_new_user : bool
            created_new_user
        user : User
            user
        """
        super().__init__('OK', created_new_user=created_new_user, user=user)
        self.is_ok = True


class ConsumeCodeIncorrectUserInputCodeErrorResult(ConsumeCodeResult):
    """ConsumeCodeIncorrectUserInputCodeErrorResult.
    """

    def __init__(self, failed_code_input_attempt_count: int,
                 maximum_code_input_attempts: int):
        """__init__.

        Parameters
        ----------
        failed_code_input_attempt_count : int
            failed_code_input_attempt_count
        maximum_code_input_attempts : int
            maximum_code_input_attempts
        """
        super().__init__('INCORRECT_USER_INPUT_CODE_ERROR',
                         failed_code_input_attempt_count=failed_code_input_attempt_count,
                         maximum_code_input_attempts=maximum_code_input_attempts)
        self.is_incorrect_user_input_code_error = True


class ConsumeCodeExpiredUserInputCodeErrorResult(ConsumeCodeResult):
    """ConsumeCodeExpiredUserInputCodeErrorResult.
    """

    def __init__(self, failed_code_input_attempt_count: int,
                 maximum_code_input_attempts: int):
        """__init__.

        Parameters
        ----------
        failed_code_input_attempt_count : int
            failed_code_input_attempt_count
        maximum_code_input_attempts : int
            maximum_code_input_attempts
        """
        super().__init__('EXPIRED_USER_INPUT_CODE_ERROR',
                         failed_code_input_attempt_count=failed_code_input_attempt_count,
                         maximum_code_input_attempts=maximum_code_input_attempts)
        self.is_expired_user_input_code_error = True


class ConsumeCodeRestartFlowErrorResult(ConsumeCodeResult):
    """ConsumeCodeRestartFlowErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('RESTART_FLOW_ERROR')
        self.is_restart_flow_error = True


class RecipeInterface(ABC):
    """RecipeInterface.
    """

    def __init__(self):
        """__init__.
        """
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_id.

        Parameters
        ----------
        user_id : str
            user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        pass

    @abstractmethod
    async def get_users_by_email(self, email: str, user_context: Dict[str, Any]) -> List[User]:
        """get_users_by_email.

        Parameters
        ----------
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        List[User]

        """
        pass

    @abstractmethod
    async def get_user_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_phone_number.

        Parameters
        ----------
        phone_number : str
            phone_number
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(self, third_party_id: str,
                                          third_party_user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_thirdparty_info.

        Parameters
        ----------
        third_party_id : str
            third_party_id
        third_party_user_id : str
            third_party_user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        pass

    @abstractmethod
    async def thirdparty_sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                                    email_verified: bool, user_context: Dict[str, Any]) -> SignInUpResult:
        """thirdparty_sign_in_up.

        Parameters
        ----------
        third_party_id : str
            third_party_id
        third_party_user_id : str
            third_party_user_id
        email : str
            email
        email_verified : bool
            email_verified
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInUpResult

        """
        pass

    @abstractmethod
    async def create_code(self,
                          email: Union[None, str],
                          phone_number: Union[None, str],
                          user_input_code: Union[None, str],
                          user_context: Dict[str, Any]) -> CreateCodeResult:
        """create_code.

        Parameters
        ----------
        email : Union[None, str]
            email
        phone_number : Union[None, str]
            phone_number
        user_input_code : Union[None, str]
            user_input_code
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateCodeResult

        """
        pass

    @abstractmethod
    async def create_new_code_for_device(self,
                                         device_id: str,
                                         user_input_code: Union[str, None],
                                         user_context: Dict[str, Any]) -> CreateNewCodeForDeviceResult:
        """create_new_code_for_device.

        Parameters
        ----------
        device_id : str
            device_id
        user_input_code : Union[str, None]
            user_input_code
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateNewCodeForDeviceResult

        """
        pass

    @abstractmethod
    async def consume_code(self,
                           pre_auth_session_id: str,
                           user_input_code: Union[str, None],
                           device_id: Union[str, None],
                           link_code: Union[str, None],
                           user_context: Dict[str, Any]) -> ConsumeCodeResult:
        """consume_code.

        Parameters
        ----------
        pre_auth_session_id : str
            pre_auth_session_id
        user_input_code : Union[str, None]
            user_input_code
        device_id : Union[str, None]
            device_id
        link_code : Union[str, None]
            link_code
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ConsumeCodeResult

        """
        pass

    @abstractmethod
    async def update_passwordless_user(self, user_id: str,
                                       email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> UpdateUserResult:
        """update_passwordless_user.

        Parameters
        ----------
        user_id : str
            user_id
        email : Union[str, None]
            email
        phone_number : Union[str, None]
            phone_number
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        UpdateUserResult

        """
        pass

    @abstractmethod
    async def revoke_all_codes(self,
                               email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> RevokeAllCodesResult:
        """revoke_all_codes.

        Parameters
        ----------
        email : Union[str, None]
            email
        phone_number : Union[str, None]
            phone_number
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        RevokeAllCodesResult

        """
        pass

    @abstractmethod
    async def revoke_code(self, code_id: str, user_context: Dict[str, Any]) -> RevokeCodeResult:
        """revoke_code.

        Parameters
        ----------
        code_id : str
            code_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        RevokeCodeResult

        """
        pass

    @abstractmethod
    async def list_codes_by_email(self, email: str, user_context: Dict[str, Any]) -> List[DeviceType]:
        """list_codes_by_email.

        Parameters
        ----------
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        List[DeviceType]

        """
        pass

    @abstractmethod
    async def list_codes_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> List[DeviceType]:
        """list_codes_by_phone_number.

        Parameters
        ----------
        phone_number : str
            phone_number
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        List[DeviceType]

        """
        pass

    @abstractmethod
    async def list_codes_by_device_id(self, device_id: str, user_context: Dict[str, Any]) -> Union[DeviceType, None]:
        """list_codes_by_device_id.

        Parameters
        ----------
        device_id : str
            device_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[DeviceType, None]

        """
        pass

    @abstractmethod
    async def list_codes_by_pre_auth_session_id(self, pre_auth_session_id: str,
                                                user_context: Dict[str, Any]) -> Union[DeviceType, None]:
        """list_codes_by_pre_auth_session_id.

        Parameters
        ----------
        pre_auth_session_id : str
            pre_auth_session_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[DeviceType, None]

        """
        pass


class ConsumeCodePostResponse(ABC):
    """ConsumeCodePostResponse.
    """

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
        """__init__.

        Parameters
        ----------
        status : Literal[
                    'OK',
                    'GENERAL_ERROR',
                    'RESTART_FLOW_ERROR',
                    'INCORRECT_USER_INPUT_CODE_ERROR',
                    'EXPIRED_USER_INPUT_CODE_ERROR'
                ]
            status
        created_new_user : Union[bool, None]
            created_new_user
        user : Union[User, None]
            user
        session : Union[SessionContainer, None]
            session
        message : Union[str, None]
            message
        failed_code_input_attempt_count : Union[int, None]
            failed_code_input_attempt_count
        maximum_code_input_attempts : Union[int, None]
            maximum_code_input_attempts
        """
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


class ConsumeCodePostOkResponse(ConsumeCodePostResponse):
    """ConsumeCodePostOkResponse.
    """

    def __init__(self, created_new_user: bool, user: User, session: SessionContainer):
        """__init__.

        Parameters
        ----------
        created_new_user : bool
            created_new_user
        user : User
            user
        session : SessionContainer
            session
        """
        super().__init__(
            status='OK',
            created_new_user=created_new_user,
            user=user,
            session=session)
        self.is_ok = True

    def to_json(self):
        """to_json.
        """
        if self.user is None:
            raise Exception("Should never come here")
        user = {
            'id': self.user.user_id,
            'time_joined': self.user.time_joined
        }
        if self.user.email is not None:
            user = {
                **user,
                'email': self.user.email
            }
        if self.user.phone_number is not None:
            user = {
                **user,
                'phoneNumber': self.user.email
            }
        return {
            'status': self.status,
            'createdNewUser': self.created_new_user,
            'user': user
        }


class ConsumeCodePostRestartFlowErrorResponse(ConsumeCodePostResponse):
    """ConsumeCodePostRestartFlowErrorResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__(
            status='RESTART_FLOW_ERROR'
        )
        self.is_restart_flow_error = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status
        }


class ConsumeCodePostGeneralErrorResponse(ConsumeCodePostResponse):
    """ConsumeCodePostGeneralErrorResponse.
    """

    def __init__(
            self,
            message: str):
        """__init__.

        Parameters
        ----------
        message : str
            message
        """
        super().__init__(
            status='GENERAL_ERROR',
            message=message
        )
        self.is_general_error = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'message': self.message
        }


class ConsumeCodePostIncorrectUserInputCodeErrorResponse(
        ConsumeCodePostResponse):
    """ConsumeCodePostIncorrectUserInputCodeErrorResponse.
    """

    def __init__(
            self,
            failed_code_input_attempt_count: int,
            maximum_code_input_attempts: int):
        """__init__.

        Parameters
        ----------
        failed_code_input_attempt_count : int
            failed_code_input_attempt_count
        maximum_code_input_attempts : int
            maximum_code_input_attempts
        """
        super().__init__(
            status='INCORRECT_USER_INPUT_CODE_ERROR',
            failed_code_input_attempt_count=failed_code_input_attempt_count,
            maximum_code_input_attempts=maximum_code_input_attempts
        )
        self.is_incorrect_user_input_code_error = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'failedCodeInputAttemptCount': self.failed_code_input_attempt_count,
            'maximumCodeInputAttempts': self.maximum_code_input_attempts
        }


class ConsumeCodePostExpiredUserInputCodeErrorResponse(
        ConsumeCodePostResponse):
    """ConsumeCodePostExpiredUserInputCodeErrorResponse.
    """

    def __init__(
            self,
            failed_code_input_attempt_count: int,
            maximum_code_input_attempts: int):
        """__init__.

        Parameters
        ----------
        failed_code_input_attempt_count : int
            failed_code_input_attempt_count
        maximum_code_input_attempts : int
            maximum_code_input_attempts
        """
        super().__init__(
            status='EXPIRED_USER_INPUT_CODE_ERROR',
            failed_code_input_attempt_count=failed_code_input_attempt_count,
            maximum_code_input_attempts=maximum_code_input_attempts
        )
        self.is_expired_user_input_code_error = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'failedCodeInputAttemptCount': self.failed_code_input_attempt_count,
            'maximumCodeInputAttempts': self.maximum_code_input_attempts
        }


class APIInterface(ABC):
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
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
        """authorisation_url_get.

        Parameters
        ----------
        provider : Provider
            provider
        api_options : ThirdPartyAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        AuthorisationUrlGetResponse

        """
        pass

    @abstractmethod
    async def thirdparty_sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None],
                                         api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> SignInUpPostResponse:
        """thirdparty_sign_in_up_post.

        Parameters
        ----------
        provider : Provider
            provider
        code : str
            code
        redirect_uri : str
            redirect_uri
        client_id : Union[str, None]
            client_id
        auth_code_response : Union[Dict[str, Any], None]
            auth_code_response
        api_options : ThirdPartyAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInUpPostResponse

        """
        pass

    @abstractmethod
    async def apple_redirect_handler_post(self, code: str, state: str,
                                          api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]):
        """apple_redirect_handler_post.

        Parameters
        ----------
        code : str
            code
        state : str
            state
        api_options : ThirdPartyAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context
        """
        pass

    @abstractmethod
    async def create_code_post(self,
                               email: Union[str, None],
                               phone_number: Union[str, None],
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> CreateCodePostResponse:
        """create_code_post.

        Parameters
        ----------
        email : Union[str, None]
            email
        phone_number : Union[str, None]
            phone_number
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateCodePostResponse

        """
        pass

    @abstractmethod
    async def resend_code_post(self,
                               device_id: str,
                               pre_auth_session_id: str,
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> ResendCodePostResponse:
        """resend_code_post.

        Parameters
        ----------
        device_id : str
            device_id
        pre_auth_session_id : str
            pre_auth_session_id
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ResendCodePostResponse

        """
        pass

    @abstractmethod
    async def consume_code_post(self,
                                pre_auth_session_id: str,
                                user_input_code: Union[str, None],
                                device_id: Union[str, None],
                                link_code: Union[str, None],
                                api_options: PasswordlessAPIOptions,
                                user_context: Dict[str, Any]) -> ConsumeCodePostResponse:
        """consume_code_post.

        Parameters
        ----------
        pre_auth_session_id : str
            pre_auth_session_id
        user_input_code : Union[str, None]
            user_input_code
        device_id : Union[str, None]
            device_id
        link_code : Union[str, None]
            link_code
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ConsumeCodePostResponse

        """
        pass

    @abstractmethod
    async def passwordless_user_email_exists_get(self,
                                                 email: str,
                                                 api_options: PasswordlessAPIOptions,
                                                 user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        """passwordless_user_email_exists_get.

        Parameters
        ----------
        email : str
            email
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        EmailExistsGetResponse

        """
        pass

    @abstractmethod
    async def passwordless_user_phone_number_exists_get(self,
                                                        phone_number: str,
                                                        api_options: PasswordlessAPIOptions,
                                                        user_context: Dict[str, Any]) -> PhoneNumberExistsGetResponse:
        """passwordless_user_phone_number_exists_get.

        Parameters
        ----------
        phone_number : str
            phone_number
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        PhoneNumberExistsGetResponse

        """
        pass
