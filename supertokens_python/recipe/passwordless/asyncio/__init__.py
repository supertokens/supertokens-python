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

from supertokens_python.recipe.passwordless.recipe import PasswordlessRecipe
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


async def create_code(email: Union[None, str] = None,
                      phone_number: Union[None, str] = None,
                      user_input_code: Union[None, str] = None) -> CreateCodeResult:
    return await PasswordlessRecipe.get_instance().recipe_implementation.create_code(email=email, phone_number=phone_number, user_input_code=user_input_code)


async def create_new_code_for_device(device_id: str,
                                     user_input_code: Union[str, None] = None) -> CreateNewCodeForDeviceResult:
    return await PasswordlessRecipe.get_instance().recipe_implementation.create_new_code_for_device(device_id=device_id, user_input_code=user_input_code)


async def consume_code(pre_auth_session_id: str,
                       user_input_code: Union[str, None] = None,
                       device_id: Union[str, None] = None,
                       link_code: Union[str, None] = None) -> ConsumeCodeResult:
    return await PasswordlessRecipe.get_instance().recipe_implementation.consume_code(pre_auth_session_id=pre_auth_session_id, user_input_code=user_input_code, device_id=device_id, link_code=link_code)


async def get_user_by_id(user_id: str) -> Union[User, None]:
    return await PasswordlessRecipe.get_instance().recipe_implementation.get_user_by_id(user_id=user_id)


async def get_user_by_email(email: str) -> Union[User, None]:
    return await PasswordlessRecipe.get_instance().recipe_implementation.get_user_by_email(email=email)


async def get_user_by_phone_number(phone_number: str) -> Union[User, None]:
    return await PasswordlessRecipe.get_instance().recipe_implementation.get_user_by_phone_number(phone_number=phone_number)


async def update_user(user_id: str, email: Union[str, None] = None, phone_number: Union[str, None] = None) -> UpdateUserResult:
    return await PasswordlessRecipe.get_instance().recipe_implementation.update_user(user_id=user_id, email=email, phone_number=phone_number)


async def revoke_all_codes(email: Union[str, None] = None, phone_number: Union[str, None] = None) -> RevokeAllCodesResult:
    return await PasswordlessRecipe.get_instance().recipe_implementation.revoke_all_codes(email=email, phone_number=phone_number)


async def revoke_code(code_id: str) -> RevokeCodeResult:
    return await PasswordlessRecipe.get_instance().recipe_implementation.revoke_code(code_id=code_id)


async def list_codes_by_email(email: str) -> List[DeviceType]:
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_email(email=email)


async def list_codes_by_phone_number(phone_number: str) -> List[DeviceType]:
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_phone_number(phone_number=phone_number)


async def list_codes_by_device_id(device_id: str) -> Union[DeviceType, None]:
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_device_id(device_id=device_id)


async def list_codes_by_pre_auth_session_id(pre_auth_session_id: str) -> Union[DeviceType, None]:
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_pre_auth_session_id(pre_auth_session_id=pre_auth_session_id)


async def create_magic_link(email: Union[str, None], phone_number: Union) -> str:
    return await PasswordlessRecipe.get_instance().create_magic_link(email=email, phone_number=phone_number)


async def signinup(email: Union[str, None], phone_number: Union) -> ConsumeCodeOkResult:
    return await PasswordlessRecipe.get_instance().signinup(email=email, phone_number=phone_number)
