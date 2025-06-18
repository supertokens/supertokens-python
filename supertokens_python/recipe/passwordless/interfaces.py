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
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import (
    RecipeUserId,
    User,
)
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError
from supertokens_python.types.response import APIResponse, GeneralErrorResponse

from ...supertokens import AppInfo

# if TYPE_CHECKING:
from .types import (
    DeviceType,
    PasswordlessLoginEmailTemplateVars,
    PasswordlessLoginSMSTemplateVars,
    SMSDeliveryIngredient,
)
from .utils import PasswordlessConfig


class CreateCodeOkResult:
    def __init__(
        self,
        pre_auth_session_id: str,
        code_id: str,
        device_id: str,
        user_input_code: str,
        link_code: str,
        code_life_time: int,
        time_created: int,
    ):
        self.pre_auth_session_id = pre_auth_session_id
        self.code_id = code_id
        self.device_id = device_id
        self.user_input_code = user_input_code
        self.link_code = link_code
        self.code_life_time = code_life_time
        self.time_created = time_created


class CreateNewCodeForDeviceOkResult:
    def __init__(
        self,
        pre_auth_session_id: str,
        code_id: str,
        device_id: str,
        user_input_code: str,
        link_code: str,
        code_life_time: int,
        time_created: int,
    ):
        self.pre_auth_session_id = pre_auth_session_id
        self.code_id = code_id
        self.device_id = device_id
        self.user_input_code = user_input_code
        self.link_code = link_code
        self.code_life_time = code_life_time
        self.time_created = time_created


class CreateNewCodeForDeviceRestartFlowError:
    pass


class CreateNewCodeForDeviceUserInputCodeAlreadyUsedError:
    pass


class ConsumedDevice:
    def __init__(
        self,
        pre_auth_session_id: str,
        failed_code_input_attempt_count: int,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
    ):
        self.pre_auth_session_id = pre_auth_session_id
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.email = email
        self.phone_number = phone_number

    @staticmethod
    def from_json(json: Dict[str, Any]) -> ConsumedDevice:
        return ConsumedDevice(
            pre_auth_session_id=json["preAuthSessionId"],
            failed_code_input_attempt_count=json["failedCodeInputAttemptCount"],
            email=json["email"] if "email" in json else None,
            phone_number=json["phoneNumber"] if "phoneNumber" in json else None,
        )

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "preAuthSessionId": self.pre_auth_session_id,
            "failedCodeInputAttemptCount": self.failed_code_input_attempt_count,
        }
        if self.email is not None:
            result["email"] = self.email
        if self.phone_number is not None:
            result["phoneNumber"] = self.phone_number
        return result


class ConsumeCodeOkResult:
    def __init__(
        self,
        created_new_recipe_user: bool,
        user: User,
        recipe_user_id: RecipeUserId,
        consumed_device: ConsumedDevice,
    ):
        self.created_new_recipe_user = created_new_recipe_user
        self.user = user
        self.recipe_user_id = recipe_user_id
        self.consumed_device = consumed_device


class ConsumeCodeIncorrectUserInputCodeError:
    def __init__(
        self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int
    ):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts


class ConsumeCodeExpiredUserInputCodeError:
    def __init__(
        self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int
    ):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts


class ConsumeCodeRestartFlowError:
    pass


class UpdateUserOkResult:
    pass


class UpdateUserUnknownUserIdError:
    pass


class UpdateUserEmailAlreadyExistsError:
    pass


class UpdateUserPhoneNumberAlreadyExistsError:
    pass


class RevokeAllCodesOkResult:
    pass


class RevokeCodeOkResult:
    pass


class CheckCodeOkResult:
    def __init__(self, consumed_device: ConsumedDevice):
        self.status = "OK"
        self.consumed_device = consumed_device

    def to_json(self):
        return {
            "status": self.status,
            "consumedDevice": self.consumed_device.to_json(),
        }


class CheckCodeIncorrectUserInputCodeError(ConsumeCodeIncorrectUserInputCodeError):
    pass


class CheckCodeExpiredUserInputCodeError(ConsumeCodeExpiredUserInputCodeError):
    pass


class CheckCodeRestartFlowError(ConsumeCodeRestartFlowError):
    pass


class EmailChangeNotAllowedError:
    def __init__(self, reason: str):
        self.reason = reason


class PhoneNumberChangeNotAllowedError:
    def __init__(self, reason: str):
        self.reason = reason


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_code(
        self,
        email: Union[None, str],
        phone_number: Union[None, str],
        user_input_code: Union[None, str],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> CreateCodeOkResult:
        pass

    @abstractmethod
    async def create_new_code_for_device(
        self,
        device_id: str,
        user_input_code: Union[str, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        CreateNewCodeForDeviceOkResult,
        CreateNewCodeForDeviceRestartFlowError,
        CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    ]:
        pass

    @abstractmethod
    async def consume_code(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodeOkResult,
        ConsumeCodeIncorrectUserInputCodeError,
        ConsumeCodeExpiredUserInputCodeError,
        ConsumeCodeRestartFlowError,
        LinkingToSessionUserFailedError,
    ]:
        pass

    @abstractmethod
    async def check_code(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        CheckCodeOkResult,
        CheckCodeIncorrectUserInputCodeError,
        CheckCodeExpiredUserInputCodeError,
        CheckCodeRestartFlowError,
    ]:
        pass

    @abstractmethod
    async def update_user(
        self,
        recipe_user_id: RecipeUserId,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateUserOkResult,
        UpdateUserUnknownUserIdError,
        UpdateUserEmailAlreadyExistsError,
        UpdateUserPhoneNumberAlreadyExistsError,
        EmailChangeNotAllowedError,
        PhoneNumberChangeNotAllowedError,
    ]:
        pass

    @abstractmethod
    async def delete_email_for_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[UpdateUserOkResult, UpdateUserUnknownUserIdError]:
        pass

    @abstractmethod
    async def delete_phone_number_for_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[UpdateUserOkResult, UpdateUserUnknownUserIdError]:
        pass

    @abstractmethod
    async def revoke_all_codes(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> RevokeAllCodesOkResult:
        pass

    @abstractmethod
    async def revoke_code(
        self, code_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> RevokeCodeOkResult:
        pass

    @abstractmethod
    async def list_codes_by_email(
        self, email: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        pass

    @abstractmethod
    async def list_codes_by_phone_number(
        self, phone_number: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        pass

    @abstractmethod
    async def list_codes_by_device_id(
        self, device_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        pass

    @abstractmethod
    async def list_codes_by_pre_auth_session_id(
        self, pre_auth_session_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: PasswordlessConfig,
        recipe_implementation: RecipeInterface,
        app_info: AppInfo,
        email_delivery: EmailDeliveryIngredient[PasswordlessLoginEmailTemplateVars],
        sms_delivery: SMSDeliveryIngredient[PasswordlessLoginSMSTemplateVars],
    ):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation
        self.app_info = app_info
        self.email_delivery = email_delivery
        self.sms_delivery = sms_delivery


class CreateCodePostOkResult(APIResponse):
    status: str = "OK"

    def __init__(
        self,
        device_id: str,
        pre_auth_session_id: str,
        flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ],
    ):
        self.device_id = device_id
        self.pre_auth_session_id = pre_auth_session_id
        self.flow_type = flow_type

    def to_json(self):
        return {
            "status": self.status,
            "deviceId": self.device_id,
            "preAuthSessionId": self.pre_auth_session_id,
            "flowType": self.flow_type,
        }


class ResendCodePostOkResult(APIResponse):
    status: str = "OK"

    def to_json(self):
        return {"status": self.status}


class ResendCodePostRestartFlowError(APIResponse):
    status: str = "RESTART_FLOW_ERROR"

    def to_json(self):
        return {"status": self.status}


class ConsumeCodePostOkResult(APIResponse):
    status: str = "OK"

    def __init__(
        self,
        created_new_recipe_user: bool,
        user: User,
        session: SessionContainer,
    ):
        self.created_new_recipe_user = created_new_recipe_user
        self.user = user
        self.session = session

    def to_json(self):
        return {
            "status": self.status,
            "user": self.user.to_json(),
            "createdNewRecipeUser": self.created_new_recipe_user,
        }


class ConsumeCodePostRestartFlowError(APIResponse):
    status: str = "RESTART_FLOW_ERROR"

    def to_json(self):
        return {"status": self.status}


class ConsumeCodePostIncorrectUserInputCodeError(APIResponse):
    status: str = "INCORRECT_USER_INPUT_CODE_ERROR"

    def __init__(
        self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int
    ):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts

    def to_json(self):
        return {
            "status": self.status,
            "failedCodeInputAttemptCount": self.failed_code_input_attempt_count,
            "maximumCodeInputAttempts": self.maximum_code_input_attempts,
        }


class ConsumeCodePostExpiredUserInputCodeError(APIResponse):
    status: str = "EXPIRED_USER_INPUT_CODE_ERROR"

    def __init__(
        self, failed_code_input_attempt_count: int, maximum_code_input_attempts: int
    ):
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.maximum_code_input_attempts = maximum_code_input_attempts

    def to_json(self):
        return {
            "status": self.status,
            "failedCodeInputAttemptCount": self.failed_code_input_attempt_count,
            "maximumCodeInputAttempts": self.maximum_code_input_attempts,
        }


class PhoneNumberExistsGetOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, exists: bool):
        self.exists = exists

    def to_json(self):
        return {"status": self.status, "exists": self.exists}


class EmailExistsGetOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, exists: bool):
        self.exists = exists

    def to_json(self):
        return {"status": self.status, "exists": self.exists}


class SignInUpPostNotAllowedResponse(APIResponse):
    status: str = "SIGN_IN_UP_NOT_ALLOWED"

    def __init__(self, reason: str):
        self.reason = reason

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "reason": self.reason}


class APIInterface:
    def __init__(self):
        self.disable_create_code_post = False
        self.disable_resend_code_post = False
        self.disable_consume_code_post = False
        self.disable_email_exists_get = False
        self.disable_phone_number_exists_get = False

    @abstractmethod
    async def create_code_post(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        CreateCodePostOkResult, SignInUpPostNotAllowedResponse, GeneralErrorResponse
    ]:
        pass

    @abstractmethod
    async def resend_code_post(
        self,
        device_id: str,
        pre_auth_session_id: str,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ResendCodePostOkResult, ResendCodePostRestartFlowError, GeneralErrorResponse
    ]:
        pass

    @abstractmethod
    async def consume_code_post(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodePostOkResult,
        ConsumeCodePostRestartFlowError,
        GeneralErrorResponse,
        ConsumeCodePostIncorrectUserInputCodeError,
        ConsumeCodePostExpiredUserInputCodeError,
        SignInUpPostNotAllowedResponse,
    ]:
        pass

    @abstractmethod
    async def email_exists_get(
        self,
        email: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailExistsGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def phone_number_exists_get(
        self,
        phone_number: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[PhoneNumberExistsGetOkResult, GeneralErrorResponse]:
        pass
