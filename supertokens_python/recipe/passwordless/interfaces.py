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

from supertokens_python.types import APIResponse

from .types import DeviceType, User
from .utils import PasswordlessConfig


class CreateCodeOkResult():
    def __init__(self, pre_auth_session_id: str, code_id: str, device_id: str,
                 user_input_code: str, link_code: str, code_life_time: int, time_created: int):
        self.pre_auth_session_id = pre_auth_session_id
        self.code_id = code_id
        self.device_id = device_id
        self.user_input_code = user_input_code
        self.link_code = link_code
        self.code_life_time = code_life_time
        self.time_created = time_created


class CreateNewCodeForDeviceOkResult():
    def __init__(self,
                 pre_auth_session_id: str,
                 code_id: str,
                 device_id: str,
                 user_input_code: str,
                 link_code: str,
                 code_life_time: int,
                 time_created: int
                 ):
        self.pre_auth_session_id = pre_auth_session_id
        self.code_id = code_id
        self.device_id = device_id
        self.user_input_code = user_input_code
        self.link_code = link_code
        self.code_life_time = code_life_time
        self.time_created = time_created


class CreateNewCodeForDeviceRestartFlowErrorResult():
    pass


class CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult():
    pass


class ConsumeCodeOkResult():
    def __init__(self, created_new_user: bool, user: User):
        self.created_new_user = created_new_user
        self.user = user


class ConsumeCodeIncorrectUserInputCodeErrorResult():
    def __init__(self, failed_code_input_attempt_count: int,
                 maximum_code_input_attempts: int):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts


class ConsumeCodeExpiredUserInputCodeErrorResult():
    def __init__(self, failed_code_input_attempt_count: int,
                 maximum_code_input_attempts: int):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts


class ConsumeCodeRestartFlowErrorResult():
    pass


class UpdateUserOkResult():
    pass


class UpdateUserUnknownUserIdErrorResult():
    pass


class UpdateUserEmailAlreadyExistsErrorResult():
    pass


class UpdateUserPhoneNumberAlreadyExistsErrorResult():
    pass


class DeleteUserInfoOkResult():
    pass


class DeleteUserInfoUnknownUserIdErrorResult():
    pass


class RevokeAllCodesOkResult():
    pass


class RevokeCodeOkResult():
    pass


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_code(self,
                          email: Union[None, str],
                          phone_number: Union[None, str],
                          user_input_code: Union[None, str],
                          user_context: Dict[str, Any]) -> CreateCodeOkResult:
        pass

    @abstractmethod
    async def create_new_code_for_device(self,
                                         device_id: str,
                                         user_input_code: Union[str, None],
                                         user_context: Dict[str, Any]) -> Union[CreateNewCodeForDeviceOkResult, CreateNewCodeForDeviceRestartFlowErrorResult, CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult]:
        pass

    @abstractmethod
    async def consume_code(self,
                           pre_auth_session_id: str,
                           user_input_code: Union[str, None],
                           device_id: Union[str, None],
                           link_code: Union[str, None],
                           user_context: Dict[str, Any]) -> Union[ConsumeCodeOkResult, ConsumeCodeIncorrectUserInputCodeErrorResult, ConsumeCodeExpiredUserInputCodeErrorResult, ConsumeCodeRestartFlowErrorResult]:
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
                          email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> Union[UpdateUserOkResult, UpdateUserUnknownUserIdErrorResult, UpdateUserEmailAlreadyExistsErrorResult, UpdateUserPhoneNumberAlreadyExistsErrorResult]:
        pass

    @abstractmethod
    async def delete_email_for_user(self, user_id: str, user_context: Dict[str, Any]) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdErrorResult]:
        pass

    @abstractmethod
    async def delete_phone_number_for_user(self, user_id: str, user_context: Dict[str, Any]) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdErrorResult]:
        pass

    @abstractmethod
    async def revoke_all_codes(self,
                               email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> RevokeAllCodesOkResult:
        pass

    @abstractmethod
    async def revoke_code(self, code_id: str, user_context: Dict[str, Any]) -> RevokeCodeOkResult:
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


class CreateCodePostOkResponse(APIResponse):
    status: str = 'OK'

    def __init__(
            self,
            device_id: str,
            pre_auth_session_id: str,
            flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']):
        self.device_id = device_id
        self.pre_auth_session_id = pre_auth_session_id
        self.flow_type = flow_type

    def to_json(self):
        return {
            'status': self.status,
            'deviceId': self.device_id,
            'preAuthSessionId': self.pre_auth_session_id,
            'flowType': self.flow_type
        }


class CreateCodePostGeneralErrorResponse(APIResponse):
    status: str = 'GENERAL_ERROR'

    def __init__(
            self,
            message: str):
        self.message = message

    def to_json(self):
        return {
            'status': self.status,
            'message': self.message
        }


class ResendCodePostOkResponse(APIResponse):
    status: str = 'OK'

    def to_json(self):
        return {
            'status': self.status
        }


class ResendCodePostRestartFlowErrorResponse(APIResponse):
    status: str = 'RESTART_FLOW_ERROR'

    def to_json(self):
        return {
            'status': self.status
        }


class ResendCodePostGeneralErrorResponse(APIResponse):
    status: str = 'GENERAL_ERROR'

    def __init__(self, message: str):
        self.message = message

    def to_json(self):
        return {
            'status': self.status,
            'message': self.message
        }


class ConsumeCodePostOkResponse(APIResponse):
    status: str = 'OK'

    def __init__(self, created_new_user: bool, user: User, session: SessionContainer):
        self.created_new_user = created_new_user
        self.user = user
        self.session = session

    def to_json(self):
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


class ConsumeCodePostRestartFlowErrorResponse(APIResponse):
    status: str = 'RESTART_FLOW_ERROR'

    def to_json(self):
        return {
            'status': self.status
        }


class ConsumeCodePostGeneralErrorResponse(APIResponse):
    status: str = 'GENERAL_ERROR'

    def __init__(
            self,
            message: str):
        self.message = message

    def to_json(self):
        return {
            'status': self.status,
            'message': self.message
        }


class ConsumeCodePostIncorrectUserInputCodeErrorResponse(
        APIResponse):
    status: str = 'INCORRECT_USER_INPUT_CODE_ERROR'

    def __init__(
            self,
            failed_code_input_attempt_count: int,
            maximum_code_input_attempts: int):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts

    def to_json(self):
        return {
            'status': self.status,
            'failedCodeInputAttemptCount': self.failed_code_input_attempt_count,
            'maximumCodeInputAttempts': self.maximum_code_input_attempts
        }


class ConsumeCodePostExpiredUserInputCodeErrorResponse(
        APIResponse):
    status: str = 'EXPIRED_USER_INPUT_CODE_ERROR'

    def __init__(
            self,
            failed_code_input_attempt_count: int,
            maximum_code_input_attempts: int):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts

    def to_json(self):
        return {
            'status': self.status,
            'failedCodeInputAttemptCount': self.failed_code_input_attempt_count,
            'maximumCodeInputAttempts': self.maximum_code_input_attempts
        }


class PhoneNumberExistsGetOkResponse(APIResponse):
    status: str = 'OK'

    def __init__(self, exists: bool):
        self.exists = exists

    def to_json(self):
        return {
            'status': self.status,
            'exists': self.exists
        }


class EmailExistsGetOkResponse(APIResponse):
    status: str = 'OK'

    def __init__(self, exists: bool):
        self.exists = exists

    def to_json(self):
        return {
            'status': self.status,
            'exists': self.exists
        }


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
                               user_context: Dict[str, Any]) -> Union[CreateCodePostOkResponse, CreateCodePostGeneralErrorResponse]:
        pass

    @abstractmethod
    async def resend_code_post(self,
                               device_id: str,
                               pre_auth_session_id: str,
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> Union[ResendCodePostOkResponse, ResendCodePostRestartFlowErrorResponse, ResendCodePostGeneralErrorResponse]:
        pass

    @abstractmethod
    async def consume_code_post(self,
                                pre_auth_session_id: str,
                                user_input_code: Union[str, None],
                                device_id: Union[str, None],
                                link_code: Union[str, None],
                                api_options: APIOptions,
                                user_context: Dict[str, Any]) -> Union[ConsumeCodePostOkResponse, ConsumeCodePostRestartFlowErrorResponse, ConsumeCodePostGeneralErrorResponse, ConsumeCodePostIncorrectUserInputCodeErrorResponse, ConsumeCodePostExpiredUserInputCodeErrorResponse]:
        pass

    @abstractmethod
    async def email_exists_get(self,
                               email: str,
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> EmailExistsGetOkResponse:
        pass

    @abstractmethod
    async def phone_number_exists_get(self,
                                      phone_number: str,
                                      api_options: APIOptions,
                                      user_context: Dict[str, Any]) -> PhoneNumberExistsGetOkResponse:
        pass
