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
from supertokens_python.auth_utils import LinkingToSessionUserFailedError
from supertokens_python.recipe.passwordless import asyncio
from supertokens_python.recipe.passwordless.interfaces import (
    CheckCodeExpiredUserInputCodeError,
    CheckCodeIncorrectUserInputCodeError,
    CheckCodeOkResult,
    CheckCodeRestartFlowError,
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeOkResult,
    ConsumeCodeRestartFlowError,
    CreateCodeOkResult,
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceRestartFlowError,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    EmailChangeNotAllowedError,
    PhoneNumberChangeNotAllowedError,
    RevokeAllCodesOkResult,
    RevokeCodeOkResult,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserOkResult,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)
from supertokens_python.recipe.passwordless.types import (
    DeviceType,
    EmailTemplateVars,
    SMSTemplateVars,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import RecipeUserId


def create_code(
    tenant_id: str,
    email: Union[None, str] = None,
    phone_number: Union[None, str] = None,
    user_input_code: Union[None, str] = None,
    session: Optional[SessionContainer] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> CreateCodeOkResult:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.create_code(
            tenant_id,
            email=email,
            phone_number=phone_number,
            user_input_code=user_input_code,
            session=session,
            user_context=user_context,
        )
    )


def create_new_code_for_device(
    tenant_id: str,
    device_id: str,
    user_input_code: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceRestartFlowError,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.create_new_code_for_device(
            tenant_id,
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
    session: Optional[SessionContainer] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    ConsumeCodeOkResult,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeRestartFlowError,
    LinkingToSessionUserFailedError,
]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.consume_code(
            tenant_id,
            pre_auth_session_id=pre_auth_session_id,
            user_input_code=user_input_code,
            device_id=device_id,
            link_code=link_code,
            session=session,
            user_context=user_context,
        )
    )


def update_user(
    recipe_user_id: RecipeUserId,
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    UpdateUserOkResult,
    UpdateUserUnknownUserIdError,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserPhoneNumberAlreadyExistsError,
    EmailChangeNotAllowedError,
    PhoneNumberChangeNotAllowedError,
]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.update_user(
            recipe_user_id=recipe_user_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )


def delete_email_for_user(
    recipe_user_id: RecipeUserId,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[UpdateUserOkResult, UpdateUserUnknownUserIdError]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.delete_email_for_user(
            recipe_user_id=recipe_user_id,
            user_context=user_context,
        )
    )


def delete_phone_number_for_user(
    recipe_user_id: RecipeUserId,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[UpdateUserOkResult, UpdateUserUnknownUserIdError]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.delete_phone_number_for_user(
            recipe_user_id=recipe_user_id,
            user_context=user_context,
        )
    )


def revoke_all_codes(
    tenant_id: str,
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> RevokeAllCodesOkResult:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.revoke_all_codes(
            tenant_id, email=email, phone_number=phone_number, user_context=user_context
        )
    )


def revoke_code(
    tenant_id: str, code_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> RevokeCodeOkResult:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.revoke_code(tenant_id, code_id=code_id, user_context=user_context)
    )


def list_codes_by_email(
    tenant_id: str, email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[DeviceType]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.list_codes_by_email(tenant_id, email=email, user_context=user_context)
    )


def list_codes_by_phone_number(
    tenant_id: str, phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[DeviceType]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.list_codes_by_phone_number(
            tenant_id, phone_number=phone_number, user_context=user_context
        )
    )


def list_codes_by_device_id(
    tenant_id: str,
    device_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[DeviceType, None]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.list_codes_by_device_id(
            tenant_id=tenant_id, device_id=device_id, user_context=user_context
        )
    )


def list_codes_by_pre_auth_session_id(
    tenant_id: str,
    pre_auth_session_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[DeviceType, None]:
    if user_context is None:
        user_context = {}
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
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.create_magic_link(
            tenant_id=tenant_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )


def signinup(
    tenant_id: str,
    email: Union[str, None],
    phone_number: Union[str, None],
    session: Optional[SessionContainer] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> ConsumeCodeOkResult:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.signinup(
            tenant_id=tenant_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
            session=session,
        )
    )


def send_email(
    input_: EmailTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return sync(asyncio.send_email(input_, user_context))


def send_sms(
    input_: SMSTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return sync(asyncio.send_sms(input_, user_context))


def check_code(
    tenant_id: str,
    pre_auth_session_id: str,
    user_input_code: Union[str, None] = None,
    device_id: Union[str, None] = None,
    link_code: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    CheckCodeOkResult,
    CheckCodeIncorrectUserInputCodeError,
    CheckCodeExpiredUserInputCodeError,
    CheckCodeRestartFlowError,
]:
    if user_context is None:
        user_context = {}
    return sync(
        asyncio.check_code(
            tenant_id,
            pre_auth_session_id=pre_auth_session_id,
            user_input_code=user_input_code,
            device_id=device_id,
            link_code=link_code,
            user_context=user_context,
        )
    )
