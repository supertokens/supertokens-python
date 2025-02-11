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

from typing import Any, Dict, Optional, Union

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.totp.types import (
    CreateDeviceOkResult,
    DeviceAlreadyExistsError,
    InvalidTOTPError,
    LimitReachedError,
    ListDevicesOkResult,
    RemoveDeviceOkResult,
    UnknownDeviceError,
    UnknownUserIdError,
    UpdateDeviceOkResult,
    VerifyDeviceOkResult,
    VerifyTOTPOkResult,
)


def create_device(
    user_id: str,
    user_identifier_info: Optional[str] = None,
    device_name: Optional[str] = None,
    skew: Optional[int] = None,
    period: Optional[int] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[CreateDeviceOkResult, DeviceAlreadyExistsError, UnknownUserIdError]:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.totp.asyncio import create_device as async_func

    return sync(
        async_func(
            user_id, user_identifier_info, device_name, skew, period, user_context
        )
    )


def update_device(
    user_id: str,
    existing_device_name: str,
    new_device_name: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[UpdateDeviceOkResult, UnknownDeviceError, DeviceAlreadyExistsError]:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.totp.asyncio import update_device as async_func

    return sync(
        async_func(user_id, existing_device_name, new_device_name, user_context)
    )


def list_devices(
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> ListDevicesOkResult:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.totp.asyncio import list_devices as async_func

    return sync(async_func(user_id, user_context))


def remove_device(
    user_id: str,
    device_name: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> RemoveDeviceOkResult:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.totp.asyncio import remove_device as async_func

    return sync(async_func(user_id, device_name, user_context))


def verify_device(
    tenant_id: str,
    user_id: str,
    device_name: str,
    totp: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    VerifyDeviceOkResult, UnknownDeviceError, InvalidTOTPError, LimitReachedError
]:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.totp.asyncio import verify_device as async_func

    return sync(async_func(tenant_id, user_id, device_name, totp, user_context))


def verify_totp(
    tenant_id: str,
    user_id: str,
    totp: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[VerifyTOTPOkResult, UnknownUserIdError, InvalidTOTPError, LimitReachedError]:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.totp.asyncio import verify_totp as async_func

    return sync(async_func(tenant_id, user_id, totp, user_context))
