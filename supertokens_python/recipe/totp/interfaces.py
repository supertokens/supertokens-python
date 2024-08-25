# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import List, Dict, Any, Union
from typing_extensions import Literal
from abc import ABC, abstractmethod

from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import APIResponse, GeneralErrorResponse


class OkResult(APIResponse):
    def __init__(self):
        self.status: Literal["OK"] = "OK"


class UserIdentifierInfoOkResult(OkResult):
    def __init__(self, info: str):
        super().__init__()
        self.info: str = info


class UnknownUserIdError(APIResponse):
    def __init__(self):
        self.status: Literal["UNKNOWN_USER_ID_ERROR"] = "UNKNOWN_USER_ID_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserIdentifierInfoDoesNotExistError:
    def __init__(self):
        self.status: Literal[
            "USER_IDENTIFIER_INFO_DOES_NOT_EXIST_ERROR"
        ] = "USER_IDENTIFIER_INFO_DOES_NOT_EXIST_ERROR"


class CreateDeviceOkResult(OkResult):
    def __init__(self, device_name: str, secret: str, qr_code_string: str):
        super().__init__()
        self.device_name: str = device_name
        self.secret: str = secret
        self.qr_code_string: str = qr_code_string

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "deviceName": self.device_name,
            "secret": self.secret,
            "qrCodeString": self.qr_code_string,
        }


class DeviceAlreadyExistsError(APIResponse):
    def __init__(self):
        self.status: Literal[
            "DEVICE_ALREADY_EXISTS_ERROR"
        ] = "DEVICE_ALREADY_EXISTS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UpdateDeviceOkResult(OkResult):
    pass


class UnknownDeviceError(APIResponse):
    def __init__(self):
        self.status: Literal["UNKNOWN_DEVICE_ERROR"] = "UNKNOWN_DEVICE_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class Device(APIResponse):
    def __init__(self, name: str, period: int, skew: int, verified: bool):
        self.name: str = name
        self.period: int = period
        self.skew: int = skew
        self.verified: bool = verified

    def to_json(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "period": self.period,
            "skew": self.skew,
            "verified": self.verified,
        }


class ListDevicesOkResult(OkResult):
    def __init__(self, devices: List[Device]):
        super().__init__()
        self.devices: List[Device] = devices

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "devices": [device.to_json() for device in self.devices],
        }


class RemoveDeviceOkResult(OkResult):
    def __init__(self, did_device_exist: bool):
        super().__init__()
        self.did_device_exist: bool = did_device_exist

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "didDeviceExist": self.did_device_exist,
        }


class VerifyDeviceOkResult(OkResult):
    def __init__(
        self,
        was_already_verified: bool,
    ):
        super().__init__()
        self.was_already_verified: bool = was_already_verified

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "wasAlreadyVerified": self.was_already_verified,
        }


class InvalidTOTPError(APIResponse):
    def __init__(
        self, current_number_of_failed_attempts: int, max_number_of_failed_attempts: int
    ):
        self.status: Literal["INVALID_TOTP_ERROR"] = "INVALID_TOTP_ERROR"
        self.current_number_of_failed_attempts: int = current_number_of_failed_attempts
        self.max_number_of_failed_attempts: int = max_number_of_failed_attempts

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "currentNumberOfFailedAttempts": self.current_number_of_failed_attempts,
            "maxNumberOfFailedAttempts": self.max_number_of_failed_attempts,
        }


class LimitReachedError(APIResponse):
    def __init__(self, retry_after_ms: int):
        self.status: Literal["LIMIT_REACHED_ERROR"] = "LIMIT_REACHED_ERROR"
        self.retry_after_ms: int = retry_after_ms

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "retryAfterMs": self.retry_after_ms,
        }


class VerifyTOTPOkResult(OkResult):
    def __init__(
        self,
    ):
        super().__init__()

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class RecipeInterface(ABC):
    @abstractmethod
    async def get_user_identifier_info_for_user_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[
        UserIdentifierInfoOkResult,
        UnknownUserIdError,
        UserIdentifierInfoDoesNotExistError,
    ]:
        pass

    @abstractmethod
    async def create_device(
        self,
        user_id: str,
        user_identifier_info: Union[str, None] = None,
        device_name: Union[str, None] = None,
        skew: Union[int, None] = None,
        period: Union[int, None] = None,
        user_context: Union[Dict[str, Any], None] = None,
    ) -> Union[CreateDeviceOkResult, DeviceAlreadyExistsError, UnknownUserIdError,]:
        pass

    @abstractmethod
    async def update_device(
        self,
        user_id: str,
        existing_device_name: str,
        new_device_name: str,
        user_context: Dict[str, Any],
    ) -> Union[UpdateDeviceOkResult, UnknownDeviceError, DeviceAlreadyExistsError,]:
        pass

    @abstractmethod
    async def list_devices(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> ListDevicesOkResult:
        pass

    @abstractmethod
    async def remove_device(
        self, user_id: str, device_name: str, user_context: Dict[str, Any]
    ) -> RemoveDeviceOkResult:
        pass

    @abstractmethod
    async def verify_device(
        self,
        tenant_id: str,
        user_id: str,
        device_name: str,
        totp: str,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifyDeviceOkResult,
        UnknownDeviceError,
        InvalidTOTPError,
        LimitReachedError,
    ]:
        pass

    @abstractmethod
    async def verify_totp(
        self, tenant_id: str, user_id: str, totp: str, user_context: Dict[str, Any]
    ) -> Union[
        VerifyTOTPOkResult,
        UnknownUserIdError,
        InvalidTOTPError,
        LimitReachedError,
    ]:
        pass


class APIOptions:
    pass


class APIInterface(ABC):
    @abstractmethod
    async def create_device_post(
        self,
        device_name: Union[str, None],
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[CreateDeviceOkResult, DeviceAlreadyExistsError, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def list_devices_get(
        self,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[ListDevicesOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def remove_device_post(
        self,
        device_name: str,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[RemoveDeviceOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def verify_device_post(
        self,
        device_name: str,
        totp: str,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifyDeviceOkResult,
        UnknownDeviceError,
        InvalidTOTPError,
        LimitReachedError,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def verify_totp_post(
        self,
        totp: str,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifyTOTPOkResult,
        UnknownUserIdError,
        InvalidTOTPError,
        LimitReachedError,
        GeneralErrorResponse,
    ]:
        pass
