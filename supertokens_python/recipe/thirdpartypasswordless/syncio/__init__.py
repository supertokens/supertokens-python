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

from typing import Any, Dict, List, Optional, Union

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.passwordless.interfaces import (
    DeleteUserInfoOkResult,
    DeleteUserInfoUnknownUserIdError,
)

from .. import asyncio, interfaces
from ..types import EmailTemplateVars, SMSTemplateVars, User


def get_user_by_id(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[None, User]:
    from ..asyncio import get_user_by_id

    return sync(get_user_by_id(user_id, user_context))


def get_user_by_third_party_info(
    tenant_id: str,
    third_party_id: str,
    third_party_user_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from ..asyncio import get_user_by_third_party_info

    return sync(
        get_user_by_third_party_info(
            tenant_id, third_party_id, third_party_user_id, user_context
        )
    )


def thirdparty_manually_create_or_update_user(
    tenant_id: str,
    third_party_id: str,
    third_party_user_id: str,
    email: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from ..asyncio import thirdparty_manually_create_or_update_user

    return sync(
        thirdparty_manually_create_or_update_user(
            tenant_id, third_party_id, third_party_user_id, email, user_context
        )
    )


def thirdparty_get_provider(
    tenant_id: str,
    third_party_id: str,
    client_type: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from ..asyncio import thirdparty_get_provider

    return sync(
        thirdparty_get_provider(tenant_id, third_party_id, client_type, user_context)
    )


def get_users_by_email(
    tenant_id: str, email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[User]:
    from ..asyncio import get_users_by_email

    return sync(get_users_by_email(tenant_id, email, user_context))


def create_code(
    tenant_id: str,
    email: Union[None, str] = None,
    phone_number: Union[None, str] = None,
    user_input_code: Union[None, str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> interfaces.CreateCodeOkResult:
    return sync(
        asyncio.create_code(
            tenant_id=tenant_id,
            email=email,
            phone_number=phone_number,
            user_input_code=user_input_code,
            user_context=user_context,
        )
    )


def create_new_code_for_device(
    tenant_id: str,
    device_id: str,
    user_input_code: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    interfaces.CreateNewCodeForDeviceOkResult,
    interfaces.CreateNewCodeForDeviceRestartFlowError,
    interfaces.CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
]:
    return sync(
        asyncio.create_new_code_for_device(
            tenant_id=tenant_id,
            device_id=device_id,
            user_input_code=user_input_code,
            user_context=user_context,
        )
    )


def consume_code(
    tenant_id: str,
    pre_auth_session_id: str,
    user_input_code: Union[str, None] = None,
    device_id: Union[str, None] = None,
    link_code: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    interfaces.ConsumeCodeOkResult,
    interfaces.ConsumeCodeIncorrectUserInputCodeError,
    interfaces.ConsumeCodeExpiredUserInputCodeError,
    interfaces.ConsumeCodeRestartFlowError,
]:
    return sync(
        asyncio.consume_code(
            tenant_id=tenant_id,
            pre_auth_session_id=pre_auth_session_id,
            user_input_code=user_input_code,
            device_id=device_id,
            link_code=link_code,
            user_context=user_context,
        )
    )


def get_user_by_phone_number(
    tenant_id: str, phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    return sync(
        asyncio.get_user_by_phone_number(
            tenant_id=tenant_id, phone_number=phone_number, user_context=user_context
        )
    )


def update_passwordless_user(
    user_id: str,
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    interfaces.PasswordlessUpdateUserOkResult,
    interfaces.PasswordlessUpdateUserUnknownUserIdError,
    interfaces.PasswordlessUpdateUserEmailAlreadyExistsError,
    interfaces.PasswordlessUpdateUserPhoneNumberAlreadyExistsError,
]:
    return sync(
        asyncio.update_passwordless_user(
            user_id=user_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )


def delete_email_for_passwordless_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    return sync(
        asyncio.delete_email_for_passwordless_user(
            user_id=user_id, user_context=user_context
        )
    )


def delete_phone_number_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    return sync(
        asyncio.delete_phone_number_for_user(user_id=user_id, user_context=user_context)
    )


def revoke_all_codes(
    tenant_id: str,
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> interfaces.RevokeAllCodesOkResult:
    return sync(
        asyncio.revoke_all_codes(
            tenant_id=tenant_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )


def revoke_code(
    tenant_id: str, code_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> interfaces.RevokeCodeOkResult:
    return sync(
        asyncio.revoke_code(
            tenant_id=tenant_id, code_id=code_id, user_context=user_context
        )
    )


def list_codes_by_email(
    tenant_id: str, email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[interfaces.DeviceType]:
    return sync(
        asyncio.list_codes_by_email(
            tenant_id=tenant_id, email=email, user_context=user_context
        )
    )


def list_codes_by_phone_number(
    tenant_id: str, phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[interfaces.DeviceType]:
    return sync(
        asyncio.list_codes_by_phone_number(
            tenant_id=tenant_id, phone_number=phone_number, user_context=user_context
        )
    )


def list_codes_by_device_id(
    tenant_id: str, device_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[interfaces.DeviceType, None]:
    return sync(
        asyncio.list_codes_by_device_id(
            tenant_id=tenant_id, device_id=device_id, user_context=user_context
        )
    )


def list_codes_by_pre_auth_session_id(
    tenant_id: str,
    pre_auth_session_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[interfaces.DeviceType, None]:
    return sync(
        asyncio.list_codes_by_pre_auth_session_id(
            tenant_id=tenant_id,
            pre_auth_session_id=pre_auth_session_id,
            user_context=user_context,
        )
    )


def create_magic_link(
    tenant_id: str,
    email: Union[str, None],
    phone_number: Union[str, None],
    user_context: Union[None, Dict[str, Any]] = None,
) -> str:
    return sync(
        asyncio.create_magic_link(
            tenant_id=tenant_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )


def passwordless_signinup(
    tenant_id: str,
    email: Union[str, None],
    phone_number: Union[str, None],
    user_context: Union[None, Dict[str, Any]] = None,
) -> interfaces.ConsumeCodeOkResult:
    return sync(
        asyncio.passwordless_signinup(
            tenant_id=tenant_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )


def send_email(
    input_: EmailTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    return sync(asyncio.send_email(input_, user_context))


def send_sms(
    input_: SMSTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    return sync(asyncio.send_sms(input_, user_context))
