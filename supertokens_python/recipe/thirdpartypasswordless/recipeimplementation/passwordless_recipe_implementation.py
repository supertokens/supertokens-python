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

from typing import Any, Dict, List, Union

from supertokens_python.recipe.passwordless.interfaces import (
    ConsumeCodeExpiredUserInputCodeErrorResult,
    ConsumeCodeIncorrectUserInputCodeErrorResult, ConsumeCodeOkResult,
    ConsumeCodeRestartFlowErrorResult, ConsumeCodeResult, CreateCodeResult,
    CreateNewCodeForDeviceResult, DeviceType, RecipeInterface,
    RevokeAllCodesResult, RevokeCodeResult, UpdateUserResult)

from ...passwordless.types import User
from ..interfaces import RecipeInterface as ThirdPartyPasswordlessInterface


class RecipeImplementation(RecipeInterface):

    def __init__(
            self, recipe_implementation: ThirdPartyPasswordlessInterface):
        super().__init__()
        self.recipe_implementation = recipe_implementation

    async def create_code(self,
                          email: Union[None, str],
                          phone_number: Union[None, str],
                          user_input_code: Union[None, str],
                          user_context: Dict[str, Any]) -> CreateCodeResult:
        return await self.recipe_implementation.create_code(email, phone_number, user_input_code, user_context)

    async def create_new_code_for_device(self,
                                         device_id: str,
                                         user_input_code: Union[str, None],
                                         user_context: Dict[str, Any]) -> CreateNewCodeForDeviceResult:
        return await self.create_new_code_for_device(device_id, user_input_code, user_context)

    async def consume_code(self,
                           pre_auth_session_id: str,
                           user_input_code: Union[str, None],
                           device_id: Union[str, None],
                           link_code: Union[str, None],
                           user_context: Dict[str, Any]) -> ConsumeCodeResult:
        result = await self.recipe_implementation.consume_code(pre_auth_session_id, user_input_code, device_id, link_code, user_context)

        if result.is_ok:
            if result.user is None or result.created_new_user is None:
                raise Exception("Should never come here")
            return ConsumeCodeOkResult(result.created_new_user, User(result.user.user_id, result.user.email, result.user.phone_number, result.user.time_joined))
        if result.is_expired_user_input_code_error:
            if result.failed_code_input_attempt_count is None or result.maximum_code_input_attempts is None:
                raise Exception("Should never come here")
            return ConsumeCodeExpiredUserInputCodeErrorResult(result.failed_code_input_attempt_count, result.maximum_code_input_attempts)
        if result.is_incorrect_user_input_code_error:
            if result.failed_code_input_attempt_count is None or result.maximum_code_input_attempts is None:
                raise Exception("Should never come here")
            return ConsumeCodeIncorrectUserInputCodeErrorResult(result.failed_code_input_attempt_count, result.maximum_code_input_attempts)

        # restart flow error
        return ConsumeCodeRestartFlowErrorResult()

    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        otherTypeUser = await self.recipe_implementation.get_user_by_id(user_id, user_context)
        if otherTypeUser is not None:
            if otherTypeUser.third_party_info is None:
                return User(otherTypeUser.user_id, otherTypeUser.email, otherTypeUser.phone_number, otherTypeUser.time_joined)

        return None

    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]:
        users = await self.recipe_implementation.get_users_by_email(email, user_context)
        for user in users:
            if user.third_party_info is not None:
                return User(user.user_id, user.email, user.phone_number, user.time_joined)

        return None

    async def get_user_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> Union[User, None]:
        otherTypeUser = await self.recipe_implementation.get_user_by_phone_number(phone_number, user_context)
        if otherTypeUser is not None:
            if otherTypeUser.third_party_info is None:
                return User(otherTypeUser.user_id, otherTypeUser.email, otherTypeUser.phone_number, otherTypeUser.time_joined)

        return None

    async def update_user(self, user_id: str,
                          email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> UpdateUserResult:
        return await self.recipe_implementation.update_passwordless_user(user_id, email, phone_number, user_context)

    async def revoke_all_codes(self,
                               email: Union[str, None], phone_number: Union[str, None], user_context: Dict[str, Any]) -> RevokeAllCodesResult:
        return await self.recipe_implementation.revoke_all_codes(email, phone_number, user_context)

    async def revoke_code(self, code_id: str, user_context: Dict[str, Any]) -> RevokeCodeResult:
        return await self.recipe_implementation.revoke_code(code_id, user_context)

    async def list_codes_by_email(self, email: str, user_context: Dict[str, Any]) -> List[DeviceType]:
        return await self.recipe_implementation.list_codes_by_email(email, user_context)

    async def list_codes_by_phone_number(self, phone_number: str, user_context: Dict[str, Any]) -> List[DeviceType]:
        return await self.recipe_implementation.list_codes_by_phone_number(phone_number, user_context)

    async def list_codes_by_device_id(self, device_id: str, user_context: Dict[str, Any]) -> Union[DeviceType, None]:
        return await self.recipe_implementation.list_codes_by_device_id(device_id, user_context)

    async def list_codes_by_pre_auth_session_id(self, pre_auth_session_id: str,
                                                user_context: Dict[str, Any]) -> Union[DeviceType, None]:
        return await self.recipe_implementation.list_codes_by_pre_auth_session_id(pre_auth_session_id, user_context)
