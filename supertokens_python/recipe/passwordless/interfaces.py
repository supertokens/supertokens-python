# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union

from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.recipe.session import SessionContainer
from typing_extensions import Literal

from .types import DeviceType, User
from .utils import PasswordlessConfig


class CreateCodeResult(ABC):
    """CreateCodeResult.
    """

    def __init__(
            self,
            status: Literal['OK'],
            pre_auth_session_id: str,
            code_id: str,
            device_id: str,
            user_input_code: str,
            link_code: str,
            code_life_time: int,
            time_created: int
    ):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        pre_auth_session_id : str
            pre_auth_session_id
        code_id : str
            code_id
        device_id : str
            device_id
        user_input_code : str
            user_input_code
        link_code : str
            link_code
        code_life_time : int
            code_life_time
        time_created : int
            time_created
        """
        self.status = status
        self.pre_auth_session_id = pre_auth_session_id
        self.code_id = code_id
        self.device_id = device_id
        self.user_input_code = user_input_code
        self.link_code = link_code
        self.code_life_time = code_life_time
        self.time_created = time_created


class CreateCodeOkResult(CreateCodeResult):
    """CreateCodeOkResult.
    """

    def __init__(self, pre_auth_session_id: str, code_id: str, device_id: str,
                 user_input_code: str, link_code: str, code_life_time: int, time_created: int):
        """__init__.

        Parameters
        ----------
        pre_auth_session_id : str
            pre_auth_session_id
        code_id : str
            code_id
        device_id : str
            device_id
        user_input_code : str
            user_input_code
        link_code : str
            link_code
        code_life_time : int
            code_life_time
        time_created : int
            time_created
        """
        super().__init__('OK', pre_auth_session_id, code_id, device_id, user_input_code, link_code, code_life_time,
                         time_created)


class CreateNewCodeForDeviceResult(ABC):
    """CreateNewCodeForDeviceResult.
    """

    def __init__(self,
                 status: Literal['OK', 'RESTART_FLOW_ERROR', 'USER_INPUT_CODE_ALREADY_USED_ERROR'],
                 pre_auth_session_id: Union[str, None] = None,
                 code_id: Union[str, None] = None,
                 device_id: Union[str, None] = None,
                 user_input_code: Union[str, None] = None,
                 link_code: Union[str, None] = None,
                 code_life_time: Union[int, None] = None,
                 time_created: Union[int, None] = None
                 ):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'RESTART_FLOW_ERROR', 'USER_INPUT_CODE_ALREADY_USED_ERROR']
            status
        pre_auth_session_id : Union[str, None]
            pre_auth_session_id
        code_id : Union[str, None]
            code_id
        device_id : Union[str, None]
            device_id
        user_input_code : Union[str, None]
            user_input_code
        link_code : Union[str, None]
            link_code
        code_life_time : Union[int, None]
            code_life_time
        time_created : Union[int, None]
            time_created
        """
        self.status = status
        self.pre_auth_session_id = pre_auth_session_id
        self.code_id = code_id
        self.device_id = device_id
        self.user_input_code = user_input_code
        self.link_code = link_code
        self.code_life_time = code_life_time
        self.time_created = time_created
        self.is_ok = False
        self.is_restart_flow_error = False
        self.is_user_input_code_already_used_error = False


class CreateNewCodeForDeviceOkResult(CreateNewCodeForDeviceResult):
    """CreateNewCodeForDeviceOkResult.
    """

    def __init__(self,
                 pre_auth_session_id: str,
                 code_id: str,
                 device_id: str,
                 user_input_code: str,
                 link_code: str,
                 code_life_time: int,
                 time_created: int
                 ):
        """__init__.

        Parameters
        ----------
        pre_auth_session_id : str
            pre_auth_session_id
        code_id : str
            code_id
        device_id : str
            device_id
        user_input_code : str
            user_input_code
        link_code : str
            link_code
        code_life_time : int
            code_life_time
        time_created : int
            time_created
        """
        super().__init__(
            'OK',
            pre_auth_session_id,
            code_id,
            device_id,
            user_input_code,
            link_code,
            code_life_time,
            time_created
        )
        self.is_ok = True


class CreateNewCodeForDeviceRestartFlowErrorResult(
        CreateNewCodeForDeviceResult):
    """CreateNewCodeForDeviceRestartFlowErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('RESTART_FLOW_ERROR')
        self.is_restart_flow_error = True


class CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult(
        CreateNewCodeForDeviceResult):
    """CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('USER_INPUT_CODE_ALREADY_USED_ERROR')
        self.is_user_input_code_already_used_error = True


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


class UpdateUserResult(ABC):
    """UpdateUserResult.
    """

    def __init__(self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR',
                 'EMAIL_ALREADY_EXISTS_ERROR', 'PHONE_NUMBER_ALREADY_EXISTS_ERROR']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'UNKNOWN_USER_ID_ERROR',
                         'EMAIL_ALREADY_EXISTS_ERROR', 'PHONE_NUMBER_ALREADY_EXISTS_ERROR']
            status
        """
        self.status = status


class UpdateUserOkResult(UpdateUserResult):
    """UpdateUserOkResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')


class UpdateUserUnknownUserIdErrorResult(UpdateUserResult):
    """UpdateUserUnknownUserIdErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('UNKNOWN_USER_ID_ERROR')


class UpdateUserEmailAlreadyExistsErrorResult(UpdateUserResult):
    """UpdateUserEmailAlreadyExistsErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR')


class UpdateUserPhoneNumberAlreadyExistsErrorResult(UpdateUserResult):
    """UpdateUserPhoneNumberAlreadyExistsErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('PHONE_NUMBER_ALREADY_EXISTS_ERROR')


class RevokeAllCodesResult(ABC):
    """RevokeAllCodesResult.
    """

    def __init__(self, status: Literal['OK']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        """
        self.status = status


class RevokeAllCodesOkResult(RevokeAllCodesResult):
    """RevokeAllCodesOkResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')


class RevokeCodeResult(ABC):
    """RevokeCodeResult.
    """

    def __init__(self, status: Literal['OK']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        """
        self.status = status


class RevokeCodeOkResult(RevokeCodeResult):
    """RevokeCodeOkResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')


class RecipeInterface(ABC):
    """RecipeInterface.
    """

    def __init__(self):
        """__init__.
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
    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_email.

        Parameters
        ----------
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

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
    async def update_user(self, user_id: str,
                          email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> UpdateUserResult:
        """update_user.

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


class APIOptions:
    """APIOptions.
    """

    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: PasswordlessConfig, recipe_implementation: RecipeInterface):
        """__init__.

        Parameters
        ----------
        request : BaseRequest
            request
        response : BaseResponse
            response
        recipe_id : str
            recipe_id
        config : PasswordlessConfig
            config
        recipe_implementation : RecipeInterface
            recipe_implementation
        """
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class CreateCodePostResponse(ABC):
    """CreateCodePostResponse.
    """

    def __init__(
        self,
        status: Literal['OK', 'GENERAL_ERROR'],
        device_id: Union[str, None] = None,
        pre_auth_session_id: Union[str, None] = None,
        flow_type: Union[None, Literal['USER_INPUT_CODE', 'MAGIC_LINK',
                                       'USER_INPUT_CODE_AND_MAGIC_LINK']] = None,
        message: Union[str, None] = None
    ):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'GENERAL_ERROR']
            status
        device_id : Union[str, None]
            device_id
        pre_auth_session_id : Union[str, None]
            pre_auth_session_id
        flow_type : Union[None, Literal['USER_INPUT_CODE', 'MAGIC_LINK',
                                               'USER_INPUT_CODE_AND_MAGIC_LINK']]
            flow_type
        message : Union[str, None]
            message
        """
        self.status = status
        self.device_id = device_id
        self.pre_auth_session_id = pre_auth_session_id
        self.flow_type = flow_type
        self.message = message
        self.is_ok = False
        self.is_general_error = False

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        pass


class CreateCodePostOkResponse(CreateCodePostResponse):
    """CreateCodePostOkResponse.
    """

    def __init__(
            self,
            device_id: str,
            pre_auth_session_id: str,
            flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']):
        """__init__.

        Parameters
        ----------
        device_id : str
            device_id
        pre_auth_session_id : str
            pre_auth_session_id
        flow_type : Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']
            flow_type
        """
        super().__init__(
            status='OK',
            device_id=device_id,
            pre_auth_session_id=pre_auth_session_id,
            flow_type=flow_type
        )
        self.is_ok = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'deviceId': self.device_id,
            'preAuthSessionId': self.pre_auth_session_id,
            'flowType': self.flow_type
        }


class CreateCodePostGeneralErrorResponse(CreateCodePostResponse):
    """CreateCodePostGeneralErrorResponse.
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


class ResendCodePostResponse(ABC):
    """ResendCodePostResponse.
    """

    def __init__(
        self,
        status: Literal['OK', 'GENERAL_ERROR', 'RESTART_FLOW_ERROR'],
        message: Union[str, None] = None
    ):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'GENERAL_ERROR', 'RESTART_FLOW_ERROR']
            status
        message : Union[str, None]
            message
        """
        self.status = status
        self.message = message
        self.is_ok = False
        self.is_general_error = False
        self.is_restart_flow_error = False

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        pass


class ResendCodePostOkResponse(ResendCodePostResponse):
    """ResendCodePostOkResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__(status='OK')
        self.is_ok = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status
        }


class ResendCodePostRestartFlowErrorResponse(ResendCodePostResponse):
    """ResendCodePostRestartFlowErrorResponse.
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


class ResendCodePostGeneralErrorResponse(ResendCodePostResponse):
    """ResendCodePostGeneralErrorResponse.
    """

    def __init__(self, message: str):
        """__init__.

        Parameters
        ----------
        message : str
            message
        """
        super().__init__(status='GENERAL_ERROR', message=message)
        self.is_general_error = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'message': self.message
        }


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

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        pass


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
                'phoneNumber': self.user.phone_number
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


class PhoneNumberExistsGetResponse(ABC):
    """PhoneNumberExistsGetResponse.
    """

    def __init__(
        self,
        status: Literal['OK'],
        exists: bool
    ):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        exists : bool
            exists
        """
        self.status = status
        self.exists = exists

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'exists': self.exists
        }


class PhoneNumberExistsGetOkResponse(PhoneNumberExistsGetResponse):
    """PhoneNumberExistsGetOkResponse.
    """

    def __init__(self, exists: bool):
        """__init__.

        Parameters
        ----------
        exists : bool
            exists
        """
        super().__init__(status='OK', exists=exists)


class EmailExistsGetResponse(ABC):
    """EmailExistsGetResponse.
    """

    def __init__(
        self,
        status: Literal['OK'],
        exists: bool
    ):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        exists : bool
            exists
        """
        self.status = status
        self.exists = exists

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'exists': self.exists
        }


class EmailExistsGetOkResponse(EmailExistsGetResponse):
    """EmailExistsGetOkResponse.
    """

    def __init__(self, exists: bool):
        """__init__.

        Parameters
        ----------
        exists : bool
            exists
        """
        super().__init__(status='OK', exists=exists)


class APIInterface:
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
        self.disable_create_code_post = False
        self.disable_resend_code_post = False
        self.disable_consume_code_post = False
        self.disable_email_exists_get = False
        self.disable_phone_number_exists_get = False

    @abstractmethod
    async def create_code_post(self,
                               email: Union[str, None],
                               phone_number: Union[str, None],
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> CreateCodePostResponse:
        """create_code_post.

        Parameters
        ----------
        email : Union[str, None]
            email
        phone_number : Union[str, None]
            phone_number
        api_options : APIOptions
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
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> ResendCodePostResponse:
        """resend_code_post.

        Parameters
        ----------
        device_id : str
            device_id
        pre_auth_session_id : str
            pre_auth_session_id
        api_options : APIOptions
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
                                api_options: APIOptions,
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
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ConsumeCodePostResponse

        """
        pass

    @abstractmethod
    async def email_exists_get(self,
                               email: str,
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        """email_exists_get.

        Parameters
        ----------
        email : str
            email
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        EmailExistsGetResponse

        """
        pass

    @abstractmethod
    async def phone_number_exists_get(self,
                                      phone_number: str,
                                      api_options: APIOptions,
                                      user_context: Dict[str, Any]) -> PhoneNumberExistsGetResponse:
        """phone_number_exists_get.

        Parameters
        ----------
        phone_number : str
            phone_number
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        PhoneNumberExistsGetResponse

        """
        pass
