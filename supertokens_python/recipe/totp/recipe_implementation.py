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
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from urllib.parse import quote

from supertokens_python.asyncio import get_user
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.totp.interfaces import (
    RecipeInterface,
)

from .types import (
    CreateDeviceOkResult,
    Device,
    DeviceAlreadyExistsError,
    InvalidTOTPError,
    LimitReachedError,
    ListDevicesOkResult,
    RemoveDeviceOkResult,
    TOTPNormalisedConfig,
    UnknownDeviceError,
    UnknownUserIdError,
    UpdateDeviceOkResult,
    UserIdentifierInfoDoesNotExistError,
    UserIdentifierInfoOkResult,
    VerifyDeviceOkResult,
    VerifyTOTPOkResult,
)

if TYPE_CHECKING:
    from supertokens_python.querier import Querier


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        config: TOTPNormalisedConfig,
    ):
        super().__init__()
        self.querier = querier
        self.config = config

    async def get_user_identifier_info_for_user_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[
        UserIdentifierInfoOkResult,
        UnknownUserIdError,
        UserIdentifierInfoDoesNotExistError,
    ]:
        user = await get_user(user_id, user_context)

        if user is None:
            return UnknownUserIdError()

        primary_login_method = next(
            (
                method
                for method in user.login_methods
                if method.recipe_user_id.get_as_string() == user.id
            ),
            None,
        )

        if primary_login_method is not None:
            if primary_login_method.email is not None:
                return UserIdentifierInfoOkResult(primary_login_method.email)
            elif primary_login_method.phone_number is not None:
                return UserIdentifierInfoOkResult(primary_login_method.phone_number)

        if user.emails:
            return UserIdentifierInfoOkResult(user.emails[0])
        elif user.phone_numbers:
            return UserIdentifierInfoOkResult(user.phone_numbers[0])

        return UserIdentifierInfoDoesNotExistError()

    async def create_device(
        self,
        user_id: str,
        user_identifier_info: Optional[str],
        device_name: Optional[str],
        skew: Optional[int],
        period: Optional[int],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateDeviceOkResult,
        DeviceAlreadyExistsError,
        UnknownUserIdError,
    ]:
        if user_identifier_info is None:
            email_or_phone_info = await self.get_user_identifier_info_for_user_id(
                user_id, user_context
            )
            if isinstance(email_or_phone_info, UserIdentifierInfoOkResult):
                user_identifier_info = email_or_phone_info.info
            elif isinstance(email_or_phone_info, UnknownUserIdError):
                return UnknownUserIdError()

        data = {
            "userId": user_id,
            "skew": skew if skew is not None else self.config.default_skew,
            "period": period if period is not None else self.config.default_period,
        }
        if device_name is not None:
            data["deviceName"] = device_name
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/totp/device"),
            data,
            user_context=user_context,
        )

        qr_code_string = (
            f"otpauth://totp/{quote(self.config.issuer)}"
            f"{':' + quote(user_identifier_info) if user_identifier_info is not None else ''}"
            f"?secret={response['secret']}&issuer={quote(self.config.issuer)}&digits=6"
            f"&period={period if period is not None else self.config.default_period}"
        )

        return CreateDeviceOkResult(
            device_name=response["deviceName"],
            secret=response["secret"],
            qr_code_string=qr_code_string,
        )

    async def update_device(
        self,
        user_id: str,
        existing_device_name: str,
        new_device_name: str,
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateDeviceOkResult,
        UnknownDeviceError,
        DeviceAlreadyExistsError,
    ]:
        # Prepare the data for the API request
        data = {
            "userId": user_id,
            "existingDeviceName": existing_device_name,
            "newDeviceName": new_device_name,
        }

        # Send a PUT request to update the device
        resp = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/totp/device"),
            data,
            None,
            user_context=user_context,
        )

        # Handle the response based on the status
        if resp["status"] == "OK":
            return UpdateDeviceOkResult()
        elif resp["status"] == "UNKNOWN_DEVICE_ERROR":
            return UnknownDeviceError()
        elif resp["status"] == "DEVICE_ALREADY_EXISTS_ERROR":
            return DeviceAlreadyExistsError()
        else:
            # Raise an exception for unknown errors
            raise Exception("Unknown error")

    async def list_devices(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> ListDevicesOkResult:
        params = {"userId": user_id}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/totp/device/list"),
            params,
            user_context=user_context,
        )
        return ListDevicesOkResult(
            devices=[
                Device(
                    name=device["name"],
                    period=device["period"],
                    skew=device["skew"],
                    verified=device["verified"],
                )
                for device in response["devices"]
            ]
        )

    async def remove_device(
        self, user_id: str, device_name: str, user_context: Dict[str, Any]
    ) -> RemoveDeviceOkResult:
        data = {"userId": user_id, "deviceName": device_name}
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/totp/device/remove"),
            data,
            user_context=user_context,
        )
        return RemoveDeviceOkResult(did_device_exist=response["didDeviceExist"])

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
        data = {"userId": user_id, "deviceName": device_name, "totp": totp}
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/totp/device/verify"),
            data,
            user_context=user_context,
        )
        if response["status"] == "OK":
            return VerifyDeviceOkResult(
                was_already_verified=response["wasAlreadyVerified"]
            )
        elif response["status"] == "UNKNOWN_DEVICE_ERROR":
            return UnknownDeviceError()
        elif response["status"] == "INVALID_TOTP_ERROR":
            return InvalidTOTPError(
                current_number_of_failed_attempts=response[
                    "currentNumberOfFailedAttempts"
                ],
                max_number_of_failed_attempts=response["maxNumberOfFailedAttempts"],
            )
        elif response["status"] == "LIMIT_REACHED_ERROR":
            return LimitReachedError(
                retry_after_ms=response["retryAfterMs"],
            )
        else:
            raise Exception("Unknown error")

    async def verify_totp(
        self, tenant_id: str, user_id: str, totp: str, user_context: Dict[str, Any]
    ) -> Union[
        VerifyTOTPOkResult,
        UnknownUserIdError,
        InvalidTOTPError,
        LimitReachedError,
    ]:
        data = {"userId": user_id, "totp": totp}
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/totp/verify"),
            data,
            user_context=user_context,
        )
        if response["status"] == "OK":
            return VerifyTOTPOkResult()
        elif response["status"] == "UNKNOWN_USER_ID_ERROR":
            return UnknownUserIdError()
        elif response["status"] == "INVALID_TOTP_ERROR":
            return InvalidTOTPError(
                current_number_of_failed_attempts=response[
                    "currentNumberOfFailedAttempts"
                ],
                max_number_of_failed_attempts=response["maxNumberOfFailedAttempts"],
            )
        elif response["status"] == "LIMIT_REACHED_ERROR":
            return LimitReachedError(
                retry_after_ms=response["retryAfterMs"],
            )
        else:
            raise Exception("Unknown error")
