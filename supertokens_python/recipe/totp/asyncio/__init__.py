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

from typing import Optional, Union, Dict, Any
from ..interfaces import (
    CreateDeviceOkResult,
    VerifyDeviceOkResult,
    VerifyCodeOkResult,
    ListTotpDevicesOkResult,
    RemoveTotpDeviceOkResult,
)
from ..interfaces import (
    DeviceAlreadyExistsError,
    InvalidTotpError,
    TotpNotEnabledError,
    LimitReachedError,
    UnknownDeviceError,
)


async def create_totp_device(
    user_id: str,
    device_name: str,
    skew: Optional[int] = None,
    period: Optional[int] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[CreateDeviceOkResult, DeviceAlreadyExistsError]:
    ...


async def verify_code(
    user_id: str, code: str, user_context: Optional[Dict[str, Any]] = None
) -> Union[
    VerifyDeviceOkResult, InvalidTotpError, TotpNotEnabledError, LimitReachedError
]:
    ...


async def verify_device(
    user_id: str,
    device_name: str,
    code: int,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    VerifyCodeOkResult, InvalidTotpError, TotpNotEnabledError, UnknownDeviceError
]:
    ...


async def update_device(
    user_id: str,
    existing_device_name: str,
    new_device_name: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    VerifyDeviceOkResult, InvalidTotpError, TotpNotEnabledError, UnknownDeviceError
]:
    ...


async def remove_device(
    user_id: str, device_name: str, user_context: Optional[Dict[str, Any]] = None
) -> Union[RemoveTotpDeviceOkResult, TotpNotEnabledError]:
    ...


async def list_devices(
    user_id: str, user_context: Optional[Dict[str, Any]] = None
) -> Union[ListTotpDevicesOkResult, TotpNotEnabledError]:
    ...
