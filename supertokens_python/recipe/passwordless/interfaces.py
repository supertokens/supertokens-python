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
        self.status = status
        self.pre_auth_session_id = pre_auth_session_id
        self.code_id = code_id
        self.device_id = device_id
        self.user_input_code = user_input_code
        self.link_code = link_code
        self.code_life_time = code_life_time
        self.time_created = time_created


class CreateCodeOkResult(CreateCodeResult):
    def __init__(self, pre_auth_session_id: str, code_id: str, device_id: str,
                 user_input_code: str, link_code: str, code_life_time: int, time_created: int):
        super().__init__('OK', pre_auth_session_id, code_id, device_id, user_input_code, link_code, code_life_time,
                         time_created)


class CreateNewCodeForDeviceResult(ABC):
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
    def __init__(self,
                 pre_auth_session_id: str,
                 code_id: str,
                 device_id: str,
                 user_input_code: str,
                 link_code: str,
                 code_life_time: int,
                 time_created: int
                 ):
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
    def __init__(self):
        super().__init__('RESTART_FLOW_ERROR')
        self.is_restart_flow_error = True


class CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult(
        CreateNewCodeForDeviceResult):
    def __init__(self):
        super().__init__('USER_INPUT_CODE_ALREADY_USED_ERROR')
        self.is_user_input_code_already_used_error = True


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


class ConsumeCodeOkResult(ConsumeCodeResult):
    def __init__(self, created_new_user: bool, user: User):
        super().__init__('OK', created_new_user=created_new_user, user=user)
        self.is_ok = True


class ConsumeCodeIncorrectUserInputCodeErrorResult(ConsumeCodeResult):
    def __init__(self, failed_code_input_attempt_count: int,
                 maximum_code_input_attempts: int):
        super().__init__('INCORRECT_USER_INPUT_CODE_ERROR',
                         failed_code_input_attempt_count=failed_code_input_attempt_count,
                         maximum_code_input_attempts=maximum_code_input_attempts)
        self.is_incorrect_user_input_code_error = True


class ConsumeCodeExpiredUserInputCodeErrorResult(ConsumeCodeResult):
    def __init__(self, failed_code_input_attempt_count: int,
                 maximum_code_input_attempts: int):
        super().__init__('EXPIRED_USER_INPUT_CODE_ERROR',
                         failed_code_input_attempt_count=failed_code_input_attempt_count,
                         maximum_code_input_attempts=maximum_code_input_attempts)
        self.is_expired_user_input_code_error = True


class ConsumeCodeRestartFlowErrorResult(ConsumeCodeResult):
    def __init__(self):
        super().__init__('RESTART_FLOW_ERROR')
        self.is_restart_flow_error = True


class UpdateUserResult(ABC):
    def __init__(self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR',
                 'EMAIL_ALREADY_EXISTS_ERROR', 'PHONE_NUMBER_ALREADY_EXISTS_ERROR']):
        self.status = status


class UpdateUserOkResult(UpdateUserResult):
    def __init__(self):
        super().__init__('OK')


class UpdateUserUnknownUserIdErrorResult(UpdateUserResult):
    def __init__(self):
        super().__init__('UNKNOWN_USER_ID_ERROR')


class UpdateUserEmailAlreadyExistsErrorResult(UpdateUserResult):
    def __init__(self):
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR')


class UpdateUserPhoneNumberAlreadyExistsErrorResult(UpdateUserResult):
    def __init__(self):
        super().__init__('PHONE_NUMBER_ALREADY_EXISTS_ERROR')


class RevokeAllCodesResult(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status


class RevokeAllCodesOkResult(RevokeAllCodesResult):
    def __init__(self):
        super().__init__('OK')


class RevokeCodeResult(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status


class RevokeCodeOkResult(RevokeCodeResult):
    def __init__(self):
        super().__init__('OK')


class RecipeInterface(ABC):
    def __init__(self):
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
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_user_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def update_user(self, user_id: str,
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


class APIOptions:
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: PasswordlessConfig, recipe_implementation: RecipeInterface):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class CreateCodePostResponse(ABC):
    def __init__(
        self,
        status: Literal['OK', 'GENERAL_ERROR'],
        device_id: Union[str, None] = None,
        pre_auth_session_id: Union[str, None] = None,
        flow_type: Union[None, Literal['USER_INPUT_CODE', 'MAGIC_LINK',
                                       'USER_INPUT_CODE_AND_MAGIC_LINK']] = None,
        message: Union[str, None] = None
    ):
        self.status = status
        self.device_id = device_id
        self.pre_auth_session_id = pre_auth_session_id
        self.flow_type = flow_type
        self.message = message
        self.is_ok = False
        self.is_general_error = False

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        pass


class CreateCodePostOkResponse(CreateCodePostResponse):
    def __init__(
            self,
            device_id: str,
            pre_auth_session_id: str,
            flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']):
        super().__init__(
            status='OK',
            device_id=device_id,
            pre_auth_session_id=pre_auth_session_id,
            flow_type=flow_type
        )
        self.is_ok = True

    def to_json(self):
        return {
            'status': self.status,
            'deviceId': self.device_id,
            'preAuthSessionId': self.pre_auth_session_id,
            'flowType': self.flow_type
        }


class CreateCodePostGeneralErrorResponse(CreateCodePostResponse):
    def __init__(
            self,
            message: str):
        super().__init__(
            status='GENERAL_ERROR',
            message=message
        )
        self.is_general_error = True

    def to_json(self):
        return {
            'status': self.status,
            'message': self.message
        }


class ResendCodePostResponse(ABC):
    def __init__(
        self,
        status: Literal['OK', 'GENERAL_ERROR', 'RESTART_FLOW_ERROR'],
        message: Union[str, None] = None
    ):
        self.status = status
        self.message = message
        self.is_ok = False
        self.is_general_error = False
        self.is_restart_flow_error = False

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        pass


class ResendCodePostOkResponse(ResendCodePostResponse):
    def __init__(self):
        super().__init__(status='OK')
        self.is_ok = True

    def to_json(self):
        return {
            'status': self.status
        }


class ResendCodePostRestartFlowErrorResponse(ResendCodePostResponse):
    def __init__(self):
        super().__init__(
            status='RESTART_FLOW_ERROR'
        )
        self.is_restart_flow_error = True

    def to_json(self):
        return {
            'status': self.status
        }


class ResendCodePostGeneralErrorResponse(ResendCodePostResponse):
    def __init__(self, message: str):
        super().__init__(status='GENERAL_ERROR', message=message)
        self.is_general_error = True

    def to_json(self):
        return {
            'status': self.status,
            'message': self.message
        }


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

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        pass


class ConsumeCodePostOkResponse(ConsumeCodePostResponse):
    def __init__(self, created_new_user: bool, user: User, session: SessionContainer):
        super().__init__(
            status='OK',
            created_new_user=created_new_user,
            user=user,
            session=session)
        self.is_ok = True

    def to_json(self):
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
    def __init__(self):
        super().__init__(
            status='RESTART_FLOW_ERROR'
        )
        self.is_restart_flow_error = True

    def to_json(self):
        return {
            'status': self.status
        }


class ConsumeCodePostGeneralErrorResponse(ConsumeCodePostResponse):
    def __init__(
            self,
            message: str):
        super().__init__(
            status='GENERAL_ERROR',
            message=message
        )
        self.is_general_error = True

    def to_json(self):
        return {
            'status': self.status,
            'message': self.message
        }


class ConsumeCodePostIncorrectUserInputCodeErrorResponse(
        ConsumeCodePostResponse):
    def __init__(
            self,
            failed_code_input_attempt_count: int,
            maximum_code_input_attempts: int):
        super().__init__(
            status='INCORRECT_USER_INPUT_CODE_ERROR',
            failed_code_input_attempt_count=failed_code_input_attempt_count,
            maximum_code_input_attempts=maximum_code_input_attempts
        )
        self.is_incorrect_user_input_code_error = True

    def to_json(self):
        return {
            'status': self.status,
            'failedCodeInputAttemptCount': self.failed_code_input_attempt_count,
            'maximumCodeInputAttempts': self.maximum_code_input_attempts
        }


class ConsumeCodePostExpiredUserInputCodeErrorResponse(
        ConsumeCodePostResponse):
    def __init__(
            self,
            failed_code_input_attempt_count: int,
            maximum_code_input_attempts: int):
        super().__init__(
            status='EXPIRED_USER_INPUT_CODE_ERROR',
            failed_code_input_attempt_count=failed_code_input_attempt_count,
            maximum_code_input_attempts=maximum_code_input_attempts
        )
        self.is_expired_user_input_code_error = True

    def to_json(self):
        return {
            'status': self.status,
            'failedCodeInputAttemptCount': self.failed_code_input_attempt_count,
            'maximumCodeInputAttempts': self.maximum_code_input_attempts
        }


class PhoneNumberExistsGetResponse(ABC):
    def __init__(
        self,
        status: Literal['OK'],
        exists: bool
    ):
        self.status = status
        self.exists = exists

    def to_json(self):
        return {
            'status': self.status,
            'exists': self.exists
        }


class PhoneNumberExistsGetOkResponse(PhoneNumberExistsGetResponse):
    def __init__(self, exists: bool):
        super().__init__(status='OK', exists=exists)


class EmailExistsGetResponse(ABC):
    def __init__(
        self,
        status: Literal['OK'],
        exists: bool
    ):
        self.status = status
        self.exists = exists

    def to_json(self):
        return {
            'status': self.status,
            'exists': self.exists
        }


class EmailExistsGetOkResponse(EmailExistsGetResponse):
    def __init__(self, exists: bool):
        super().__init__(status='OK', exists=exists)


class APIInterface:
    def __init__(self):
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
        pass

    @abstractmethod
    async def resend_code_post(self,
                               device_id: str,
                               pre_auth_session_id: str,
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> ResendCodePostResponse:
        pass

    @abstractmethod
    async def consume_code_post(self,
                                pre_auth_session_id: str,
                                user_input_code: Union[str, None],
                                device_id: Union[str, None],
                                link_code: Union[str, None],
                                api_options: APIOptions,
                                user_context: Dict[str, Any]) -> ConsumeCodePostResponse:
        pass

    @abstractmethod
    async def email_exists_get(self,
                               email: str,
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        pass

    @abstractmethod
    async def phone_number_exists_get(self,
                                      phone_number: str,
                                      api_options: APIOptions,
                                      user_context: Dict[str, Any]) -> PhoneNumberExistsGetResponse:
        pass
