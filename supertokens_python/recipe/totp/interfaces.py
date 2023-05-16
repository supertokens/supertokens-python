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


from typing import List, Any, Dict, Optional, Union
from abc import abstractmethod
from supertokens_python.types import APIResponse
from urllib.parse import quote


class DeviceAlreadyExistsError:
    pass


class InvalidTotpError:
    pass


class TotpNotEnabledError:
    pass


class LimitReachedError:
    pass


class UnknownDeviceError:
    pass


class CreateDeviceOkResult:
    def __init__(self, user_identifier: str, issuer_name: str, secret: str):
        self.qr = f"otpauth://totp/{quote(issuer_name)}:{quote(user_identifier)}?secret={secret}&issuer={quote(issuer_name)}"


class VerifyCodeOkResult:
    pass


class VerifyDeviceOkResult:
    def __init__(self, was_already_verified: bool):
        self.was_already_verified = was_already_verified


class UpdateDeviceOkResult:
    pass


class RemoveTotpDeviceOkResult:
    def __init__(self, did_exist: bool):
        self.did_exist = did_exist


class ListTotpDevicesOkResult:
    def __init__(self, devices: List[Dict[str, Any]]):
        self.devices = devices


class RecipeInterface:
    @abstractmethod
    def create_device(
        self,
        user_id: str,
        device_name: str,
        skew: Optional[int] = None,
        period: Optional[int] = None,
    ) -> Union[CreateDeviceOkResult, DeviceAlreadyExistsError]:
        pass

    @abstractmethod
    def verify_code(
        self, user_id: str, code: int
    ) -> Union[
        VerifyCodeOkResult, InvalidTotpError, TotpNotEnabledError, LimitReachedError
    ]:
        pass

    @abstractmethod
    def verify_device(
        self, user_id: str, device_name: str, code: int
    ) -> Union[
        VerifyDeviceOkResult, InvalidTotpError, TotpNotEnabledError, UnknownDeviceError
    ]:
        pass

    @abstractmethod
    def update_device(
        self, user_id: str, existing_device_name: str, new_device_name: str
    ) -> Union[
        UpdateDeviceOkResult,
        TotpNotEnabledError,
        DeviceAlreadyExistsError,
        UnknownDeviceError,
    ]:
        pass

    @abstractmethod
    def remove_device(
        self, user_id: str, device_name: str
    ) -> Union[RemoveTotpDeviceOkResult, TotpNotEnabledError]:
        pass

    @abstractmethod
    def list_devices(
        self, user_id: str
    ) -> Union[ListTotpDevicesOkResult, TotpNotEnabledError]:
        pass


class DeviceAlreadyExistsErrorResponse(APIResponse):
    status = "DEVICE_ALREADY_EXISTS_ERROR"

    def to_json(self):
        return {"status": self.status}


class InvalidTotpErrorReponse(APIResponse):
    status = "INVALID_TOTP_ERROR"

    def to_json(self):
        return {"status": self.status}


class TotpNotEnabledErrorResponse(APIResponse):
    status = "TOTP_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


class LimitReachedErrorResponse(APIResponse):
    status = "LIMIT_REACHED_ERROR"

    def to_json(self):
        return {"status": self.status}


class UnknownDeviceErrorResponse(APIResponse):
    status = "UNKNOWN_DEVICE_ERROR"

    def to_json(self):
        return {"status": self.status}


class CreateDevicePostOkResponse(APIResponse):
    status = "OK"

    def __init__(self, user_identifier: str, issuer_name: str, secret: str):
        self.qr = f"otpauth://totp/{quote(issuer_name)}:{quote(user_identifier)}?secret={secret}&issuer={quote(issuer_name)}"

    def to_json(self):
        return {"status": self.status, "qr": self.qr}


class VerifyCodePostOkResponse(APIResponse):
    status = "OK"

    def to_json(self):
        return {"status": self.status}


class VerifyDeviceOkResponse(APIResponse):
    status = "OK"

    def __init__(self, was_already_verified: bool):
        self.was_already_verified = was_already_verified

    def to_json(self):
        return {"status": self.status, "wasAlreadyVerified": self.was_already_verified}


class UpdateDevicePutOkResponse(APIResponse):
    status = "OK"

    def to_json(self):
        return {"status": self.status}


class RemoveDevicePostOkResponse(APIResponse):
    status = "OK"

    def __init__(self, did_exist: bool):
        self.did_exist = did_exist

    def to_json(self):
        return {"status": self.status, "didExist": self.did_exist}


class ListDevicesGetOkResponse(APIResponse):
    status = "OK"

    def __init__(self, devices: List[Dict[str, Any]]):
        self.devices = devices

    def to_json(self):
        return {"status": self.status, "devices": self.devices}


class APIInterface:
    def __init__(self) -> None:
        self.disable_create_device_post = False
        self.disable_verify_code_post = False
        self.disable_verify_device_post = False
        self.disable_update_device_put = False
        self.disable_remove_device_post = False
        self.disable_list_devices_get = False

    @abstractmethod
    def create_device_post(
        self, user_id: str, device_name: str, skew: int, period: int
    ) -> Union[CreateDevicePostOkResponse, DeviceAlreadyExistsErrorResponse]:
        pass

    @abstractmethod
    def verify_code_post(
        self, user_id: str, code: int
    ) -> Union[
        VerifyCodePostOkResponse,
        InvalidTotpErrorReponse,
        TotpNotEnabledErrorResponse,
        LimitReachedErrorResponse,
    ]:
        pass

    @abstractmethod
    def verify_device_post(
        self, user_id: str, device_name: str, code: int
    ) -> Union[
        VerifyDeviceOkResponse,
        InvalidTotpErrorReponse,
        TotpNotEnabledErrorResponse,
        UnknownDeviceErrorResponse,
    ]:
        pass

    @abstractmethod
    def update_device_put(
        self, user_id: str, existing_device_name: str, new_device_name: str
    ) -> Union[
        UpdateDevicePutOkResponse,
        TotpNotEnabledErrorResponse,
        DeviceAlreadyExistsErrorResponse,
        UnknownDeviceErrorResponse,
    ]:
        pass

    @abstractmethod
    def remove_device_post(
        self, user_id: str, device_name: str
    ) -> Union[RemoveDevicePostOkResponse, TotpNotEnabledErrorResponse]:
        pass

    @abstractmethod
    def list_devices_get(
        self, user_id: str
    ) -> Union[ListDevicesGetOkResponse, TotpNotEnabledErrorResponse]:
        pass
