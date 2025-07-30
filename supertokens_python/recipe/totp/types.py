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

from typing import Any, Dict, List, Optional

from typing_extensions import Literal

from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
    BaseOverrideConfig,
)
from supertokens_python.types.response import APIResponse

from .interfaces import APIInterface, RecipeInterface


class OkResult(APIResponse):
    def __init__(self):
        self.status: Literal["OK"] = "OK"


class UserIdentifierInfoOkResult(OkResult):
    def __init__(self, info: str):
        super().__init__()
        self.info: str = info

    def to_json(self) -> Dict[str, Any]:
        raise NotImplementedError()


class UnknownUserIdError(APIResponse):
    def __init__(self):
        self.status: Literal["UNKNOWN_USER_ID_ERROR"] = "UNKNOWN_USER_ID_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserIdentifierInfoDoesNotExistError:
    def __init__(self):
        self.status: Literal["USER_IDENTIFIER_INFO_DOES_NOT_EXIST_ERROR"] = (
            "USER_IDENTIFIER_INFO_DOES_NOT_EXIST_ERROR"
        )


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
        self.status: Literal["DEVICE_ALREADY_EXISTS_ERROR"] = (
            "DEVICE_ALREADY_EXISTS_ERROR"
        )

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UpdateDeviceOkResult(OkResult):
    def to_json(self) -> Dict[str, Any]:
        raise NotImplementedError()


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
    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


TOTPOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedTOTPOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
OverrideConfig = TOTPOverrideConfig
"""Deprecated: Use `TOTPOverrideConfig` instead."""


class TOTPOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    issuer: Optional[str] = None
    default_skew: Optional[int] = None
    default_period: Optional[int] = None


class TOTPConfig(
    TOTPOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, TOTPOverrideableConfig],
):
    def to_overrideable_config(self) -> TOTPOverrideableConfig:
        """Create a `TOTPOverrideableConfig` from the current config."""
        return TOTPOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: TOTPOverrideableConfig,
    ) -> "TOTPConfig":
        """
        Create a `TOTPConfig` from a `TOTPOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return TOTPConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedTOTPConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    issuer: str
    default_skew: int
    default_period: int
