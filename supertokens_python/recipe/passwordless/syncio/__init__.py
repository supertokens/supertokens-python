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
from typing import Union, List

from supertokens_python.recipe.passwordless.interfaces import (
    CreateCodeResult,
    CreateNewCodeForDeviceResult,
    ConsumeCodeResult,
    UpdateUserResult,
    RevokeAllCodesResult,
    RevokeCodeResult,
    ConsumeCodeOkResult
)
from supertokens_python.recipe.passwordless.types import DeviceType, User
import supertokens_python.recipe.passwordless.asyncio as asyncio
from supertokens_python.async_to_sync_wrapper import sync


def create_code(email: Union[None, str] = None,
                phone_number: Union[None, str] = None,
                user_input_code: Union[None, str] = None) -> CreateCodeResult:
    return sync(asyncio.create_code(email=email, phone_number=phone_number, user_input_code=user_input_code))


def create_new_code_for_device(device_id: str,
                               user_input_code: Union[str, None] = None) -> CreateNewCodeForDeviceResult:
    return sync(asyncio.create_new_code_for_device(device_id=device_id, user_input_code=user_input_code))


def consume_code(pre_auth_session_id: str,
                 user_input_code: Union[str, None] = None,
                 device_id: Union[str, None] = None,
                 link_code: Union[str, None] = None) -> ConsumeCodeResult:
    return sync(asyncio.consume_code(pre_auth_session_id=pre_auth_session_id, user_input_code=user_input_code,
                                     device_id=device_id, link_code=link_code))


def get_user_by_id(user_id: str) -> Union[User, None]:
    return sync(asyncio.get_user_by_id(user_id=user_id))


def get_user_by_email(email: str) -> Union[User, None]:
    return sync(asyncio.get_user_by_email(email=email))


def get_user_by_phone_number(phone_number: str) -> Union[User, None]:
    return sync(asyncio.get_user_by_phone_number(phone_number=phone_number))


def update_user(user_id: str, email: Union[str, None] = None,
                phone_number: Union[str, None] = None) -> UpdateUserResult:
    return sync(asyncio.update_user(user_id=user_id, email=email, phone_number=phone_number))


def revoke_all_codes(email: Union[str, None] = None, phone_number: Union[str, None] = None) -> RevokeAllCodesResult:
    return sync(asyncio.revoke_all_codes(email=email, phone_number=phone_number))


def revoke_code(code_id: str) -> RevokeCodeResult:
    return sync(asyncio.revoke_code(code_id=code_id))


def list_codes_by_email(email: str) -> List[DeviceType]:
    return sync(asyncio.list_codes_by_email(email=email))


def list_codes_by_phone_number(phone_number: str) -> List[DeviceType]:
    return sync(asyncio.list_codes_by_phone_number(phone_number=phone_number))


def list_codes_by_device_id(device_id: str) -> Union[DeviceType, None]:
    return sync(asyncio.list_codes_by_device_id(device_id=device_id))


def list_codes_by_pre_auth_session_id(pre_auth_session_id: str) -> Union[DeviceType, None]:
    return sync(asyncio.list_codes_by_pre_auth_session_id(pre_auth_session_id=pre_auth_session_id))


def create_magic_link(email: Union[str, None], phone_number: Union) -> str:
    return sync(asyncio.create_magic_link(email=email, phone_number=phone_number))


def signinup(email: Union[str, None], phone_number: Union) -> ConsumeCodeOkResult:
    return sync(asyncio.signinup(email=email, phone_number=phone_number))
