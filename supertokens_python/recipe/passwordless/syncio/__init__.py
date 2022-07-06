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
from typing import Any, Dict, List, Union

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.passwordless import asyncio
from supertokens_python.recipe.passwordless.interfaces import (
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeOkResult,
    ConsumeCodeRestartFlowError,
    CreateCodeOkResult,
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceRestartFlowError,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    DeleteUserInfoOkResult,
    DeleteUserInfoUnknownUserIdError,
    RevokeAllCodesOkResult,
    RevokeCodeOkResult,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserOkResult,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)
from supertokens_python.recipe.passwordless.types import (
    DeviceType,
    PasswordlessLoginEmailTemplateVars,
    PasswordlessLoginSMSTemplateVars,
    User,
)


def create_code(
    email: Union[None, str] = None,
    phone_number: Union[None, str] = None,
    user_input_code: Union[None, str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> CreateCodeOkResult:
    return sync(
        asyncio.create_code(
            email=email,
            phone_number=phone_number,
            user_input_code=user_input_code,
            user_context=user_context,
        )
    )


def create_new_code_for_device(
    device_id: str,
    user_input_code: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceRestartFlowError,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
]:
    return sync(
        asyncio.create_new_code_for_device(
            device_id=device_id,
            user_input_code=user_input_code,
            user_context=user_context,
        )
    )


def consume_code(
    pre_auth_session_id: str,
    user_input_code: Union[str, None] = None,
    device_id: Union[str, None] = None,
    link_code: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    ConsumeCodeOkResult,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeRestartFlowError,
]:
    return sync(
        asyncio.consume_code(
            pre_auth_session_id=pre_auth_session_id,
            user_input_code=user_input_code,
            device_id=device_id,
            link_code=link_code,
            user_context=user_context,
        )
    )


def get_user_by_id(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    return sync(asyncio.get_user_by_id(user_id=user_id, user_context=user_context))


def get_user_by_email(
    email: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    return sync(asyncio.get_user_by_email(email=email, user_context=user_context))


def get_user_by_phone_number(
    phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    return sync(
        asyncio.get_user_by_phone_number(
            phone_number=phone_number, user_context=user_context
        )
    )


def update_user(
    user_id: str,
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    UpdateUserOkResult,
    UpdateUserUnknownUserIdError,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserPhoneNumberAlreadyExistsError,
]:
    return sync(
        asyncio.update_user(
            user_id=user_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )


def delete_email_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    return sync(
        asyncio.delete_email_for_user(user_id=user_id, user_context=user_context)
    )


def delete_phone_number_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    return sync(
        asyncio.delete_phone_number_for_user(user_id=user_id, user_context=user_context)
    )


def revoke_all_codes(
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> RevokeAllCodesOkResult:
    return sync(
        asyncio.revoke_all_codes(
            email=email, phone_number=phone_number, user_context=user_context
        )
    )


def revoke_code(
    code_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> RevokeCodeOkResult:
    return sync(asyncio.revoke_code(code_id=code_id, user_context=user_context))


def list_codes_by_email(
    email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[DeviceType]:
    return sync(asyncio.list_codes_by_email(email=email, user_context=user_context))


def list_codes_by_phone_number(
    phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[DeviceType]:
    return sync(
        asyncio.list_codes_by_phone_number(
            phone_number=phone_number, user_context=user_context
        )
    )


def list_codes_by_device_id(
    device_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeviceType, None]:
    return sync(
        asyncio.list_codes_by_device_id(device_id=device_id, user_context=user_context)
    )


def list_codes_by_pre_auth_session_id(
    pre_auth_session_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeviceType, None]:
    return sync(
        asyncio.list_codes_by_pre_auth_session_id(
            pre_auth_session_id=pre_auth_session_id, user_context=user_context
        )
    )


def create_magic_link(
    email: Union[str, None],
    phone_number: Union[str, None],
    user_context: Union[None, Dict[str, Any]] = None,
) -> str:
    return sync(
        asyncio.create_magic_link(
            email=email, phone_number=phone_number, user_context=user_context
        )
    )


def signinup(
    email: Union[str, None],
    phone_number: Union[str, None],
    user_context: Union[None, Dict[str, Any]] = None,
) -> ConsumeCodeOkResult:
    return sync(
        asyncio.signinup(
            email=email, phone_number=phone_number, user_context=user_context
        )
    )


def send_email(
    input_: PasswordlessLoginEmailTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
) -> None:
    return sync(asyncio.send_email(input_, user_context))


def send_sms(
    input_: PasswordlessLoginSMSTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
) -> None:
    return sync(asyncio.send_sms(input_, user_context))
