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

from typing import TYPE_CHECKING, Any, Dict, List, Union

from ...passwordless.interfaces import (
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
)
from ...passwordless.interfaces import (
    ConsumeCodeOkResult as PasswordlessConsumeCodeOkResult,
)
from ...passwordless.interfaces import (
    ConsumeCodeRestartFlowError,
    CreateCodeOkResult,
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceRestartFlowError,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    DeleteUserInfoOkResult,
    DeleteUserInfoUnknownUserIdError,
    DeviceType,
    RevokeAllCodesOkResult,
    RevokeCodeOkResult,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserOkResult,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)
from ...thirdparty.interfaces import SignInUpOkResult

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

from supertokens_python.recipe.passwordless.recipe_implementation import (
    RecipeImplementation as PasswordlessImplementation,
)
from supertokens_python.recipe.thirdparty.recipe_implementation import (
    RecipeImplementation as ThirdPartyImplementation,
)

from ..interfaces import ConsumeCodeOkResult, RecipeInterface
from ..types import User
from .passwordless_recipe_implementation import (
    RecipeImplementation as DerivedPasswordlessImplementation,
)
from .third_party_recipe_implementation import (
    RecipeImplementation as DerivedThirdPartyImplementation,
)


class RecipeImplementation(RecipeInterface):
    def __init__(
        self, passwordless_querier: Querier, thirdparty_querier: Union[Querier, None]
    ):
        super().__init__()
        passwordless_implementation = PasswordlessImplementation(passwordless_querier)

        self.pless_get_user_by_id = passwordless_implementation.get_user_by_id
        self.pless_get_user_by_email = passwordless_implementation.get_user_by_email
        self.pless_consume_code = passwordless_implementation.consume_code
        self.pless_create_code = passwordless_implementation.create_code
        self.pless_create_new_code_for_device = (
            passwordless_implementation.create_new_code_for_device
        )
        self.pless_get_user_by_phone_number = (
            passwordless_implementation.get_user_by_phone_number
        )
        self.pless_list_codes_by_device_id = (
            passwordless_implementation.list_codes_by_device_id
        )
        self.pless_list_codes_by_email = passwordless_implementation.list_codes_by_email
        self.pless_list_codes_by_phone_number = (
            passwordless_implementation.list_codes_by_phone_number
        )
        self.pless_list_codes_by_pre_auth_session_id = (
            passwordless_implementation.list_codes_by_pre_auth_session_id
        )
        self.pless_revoke_all_codes = passwordless_implementation.revoke_all_codes
        self.pless_revoke_code = passwordless_implementation.revoke_code
        self.pless_update_user = passwordless_implementation.update_user
        self.pless_delete_email_for_user = (
            passwordless_implementation.delete_email_for_user
        )
        self.pless_delete_phone_number_for_user = (
            passwordless_implementation.delete_phone_number_for_user
        )

        derived_pless = DerivedPasswordlessImplementation(self)
        passwordless_implementation.get_user_by_id = derived_pless.get_user_by_id
        passwordless_implementation.get_user_by_email = derived_pless.get_user_by_email
        passwordless_implementation.consume_code = derived_pless.consume_code
        passwordless_implementation.create_code = derived_pless.create_code
        passwordless_implementation.create_new_code_for_device = (
            derived_pless.create_new_code_for_device
        )
        passwordless_implementation.get_user_by_phone_number = (
            derived_pless.get_user_by_phone_number
        )
        passwordless_implementation.list_codes_by_device_id = (
            derived_pless.list_codes_by_device_id
        )
        passwordless_implementation.list_codes_by_email = (
            derived_pless.list_codes_by_email
        )
        passwordless_implementation.list_codes_by_phone_number = (
            derived_pless.list_codes_by_phone_number
        )
        passwordless_implementation.list_codes_by_pre_auth_session_id = (
            derived_pless.list_codes_by_pre_auth_session_id
        )
        passwordless_implementation.revoke_all_codes = derived_pless.revoke_all_codes
        passwordless_implementation.revoke_code = derived_pless.revoke_code
        passwordless_implementation.update_user = derived_pless.update_user
        passwordless_implementation.delete_email_for_user = (
            derived_pless.delete_email_for_user
        )
        passwordless_implementation.delete_phone_number_for_user = (
            derived_pless.delete_phone_number_for_user
        )

        self.tp_get_user_by_id = None
        self.tp_get_users_by_email = None
        self.tp_get_user_by_thirdparty_info = None
        self.tp_sign_in_up = None
        if thirdparty_querier is not None:
            thirdparty_implementation = ThirdPartyImplementation(thirdparty_querier)
            self.tp_get_user_by_id = thirdparty_implementation.get_user_by_id
            self.tp_get_users_by_email = thirdparty_implementation.get_users_by_email
            self.tp_get_user_by_thirdparty_info = (
                thirdparty_implementation.get_user_by_thirdparty_info
            )
            self.tp_sign_in_up = thirdparty_implementation.sign_in_up

            derived_tp = DerivedThirdPartyImplementation(self)
            thirdparty_implementation.get_user_by_id = derived_tp.get_user_by_id
            thirdparty_implementation.get_users_by_email = derived_tp.get_users_by_email
            thirdparty_implementation.get_user_by_thirdparty_info = (
                derived_tp.get_user_by_thirdparty_info
            )
            thirdparty_implementation.sign_in_up = derived_tp.sign_in_up

    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        pless_user = await self.pless_get_user_by_id(user_id, user_context)

        if pless_user is not None:
            return User(
                user_id=pless_user.user_id,
                email=pless_user.email,
                time_joined=pless_user.time_joined,
                third_party_info=None,
                phone_number=pless_user.phone_number,
            )

        if self.tp_get_user_by_id is None:
            return None

        tp_user = await self.tp_get_user_by_id(user_id, user_context)
        if tp_user is None:
            return None
        return User(
            user_id=tp_user.user_id,
            email=tp_user.email,
            time_joined=tp_user.time_joined,
            third_party_info=tp_user.third_party_info,
            phone_number=None,
        )

    async def get_users_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> List[User]:
        result: List[User] = []
        pless_user = await self.pless_get_user_by_email(email, user_context)

        if pless_user is not None:
            result.append(
                User(
                    user_id=pless_user.user_id,
                    email=pless_user.email,
                    time_joined=pless_user.time_joined,
                    third_party_info=None,
                    phone_number=pless_user.phone_number,
                )
            )

        if self.tp_get_users_by_email is None:
            return result

        tp_users = await self.tp_get_users_by_email(email, user_context)

        for tp_user in tp_users:
            result.append(
                User(
                    user_id=tp_user.user_id,
                    email=tp_user.email,
                    time_joined=tp_user.time_joined,
                    third_party_info=tp_user.third_party_info,
                    phone_number=None,
                )
            )

        return result

    async def get_user_by_thirdparty_info(
        self,
        third_party_id: str,
        third_party_user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[User, None]:
        if self.tp_get_user_by_thirdparty_info is None:
            return None
        tp_user = await self.tp_get_user_by_thirdparty_info(
            third_party_id, third_party_user_id, user_context
        )

        if tp_user is None:
            return None

        return User(
            user_id=tp_user.user_id,
            email=tp_user.email,
            time_joined=tp_user.time_joined,
            third_party_info=tp_user.third_party_info,
            phone_number=None,
        )

    async def thirdparty_sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        user_context: Dict[str, Any],
    ) -> SignInUpOkResult:
        if self.tp_sign_in_up is None:
            raise Exception("No thirdparty provider configured")
        return await self.tp_sign_in_up(
            third_party_id, third_party_user_id, email, user_context
        )

    async def get_user_by_phone_number(
        self, phone_number: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        pless_user = await self.pless_get_user_by_phone_number(
            phone_number, user_context
        )
        if pless_user is not None:
            return User(
                user_id=pless_user.user_id,
                email=pless_user.email,
                time_joined=pless_user.time_joined,
                third_party_info=None,
                phone_number=pless_user.phone_number,
            )

        return None

    async def create_code(
        self,
        email: Union[None, str],
        phone_number: Union[None, str],
        user_input_code: Union[None, str],
        user_context: Dict[str, Any],
    ) -> CreateCodeOkResult:
        return await self.pless_create_code(
            email, phone_number, user_input_code, user_context
        )

    async def create_new_code_for_device(
        self,
        device_id: str,
        user_input_code: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateNewCodeForDeviceOkResult,
        CreateNewCodeForDeviceRestartFlowError,
        CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    ]:
        return await self.pless_create_new_code_for_device(
            device_id, user_input_code, user_context
        )

    async def consume_code(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodeOkResult,
        ConsumeCodeIncorrectUserInputCodeError,
        ConsumeCodeExpiredUserInputCodeError,
        ConsumeCodeRestartFlowError,
    ]:
        result = await self.pless_consume_code(
            pre_auth_session_id, user_input_code, device_id, link_code, user_context
        )
        if isinstance(result, PasswordlessConsumeCodeOkResult):
            return ConsumeCodeOkResult(
                result.created_new_user,
                User(
                    result.user.user_id,
                    result.user.email,
                    result.user.phone_number,
                    None,
                    result.user.time_joined,
                ),
            )
        return result

    async def update_passwordless_user(
        self,
        user_id: str,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateUserOkResult,
        UpdateUserUnknownUserIdError,
        UpdateUserEmailAlreadyExistsError,
        UpdateUserPhoneNumberAlreadyExistsError,
    ]:
        user = await self.get_user_by_id(user_id, user_context)
        if user is None:
            return UpdateUserUnknownUserIdError()
        if user.third_party_info is not None:
            raise Exception(
                "Cannot update passwordless user info of a user who signed up using third party login."
            )
        return await self.pless_update_user(user_id, email, phone_number, user_context)

    async def delete_email_for_passwordless_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
        user = await self.get_user_by_id(user_id, user_context)
        if user is None:
            return DeleteUserInfoUnknownUserIdError()
        if user.third_party_info is not None:
            raise Exception(
                "Cannot update passwordless user info of a user who signed up using third party login."
            )
        return await self.pless_delete_email_for_user(user_id, user_context)

    async def delete_phone_number_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
        user = await self.get_user_by_id(user_id, user_context)
        if user is None:
            return DeleteUserInfoUnknownUserIdError()
        if user.third_party_info is not None:
            raise Exception(
                "Cannot update passwordless user info of a user who signed up using third party login."
            )
        return await self.pless_delete_phone_number_for_user(user_id, user_context)

    async def revoke_all_codes(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> RevokeAllCodesOkResult:
        return await self.pless_revoke_all_codes(email, phone_number, user_context)

    async def revoke_code(
        self, code_id: str, user_context: Dict[str, Any]
    ) -> RevokeCodeOkResult:
        return await self.pless_revoke_code(code_id, user_context)

    async def list_codes_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        return await self.pless_list_codes_by_email(email, user_context)

    async def list_codes_by_phone_number(
        self, phone_number: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        return await self.pless_list_codes_by_phone_number(phone_number, user_context)

    async def list_codes_by_device_id(
        self, device_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        return await self.pless_list_codes_by_device_id(device_id, user_context)

    async def list_codes_by_pre_auth_session_id(
        self, pre_auth_session_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        return await self.pless_list_codes_by_pre_auth_session_id(
            pre_auth_session_id, user_context
        )
