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
from supertokens_python import get_request_from_user_context

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
from supertokens_python.recipe.passwordless.recipe import PasswordlessRecipe
from supertokens_python.recipe.passwordless.types import (
    DeviceType,
    EmailTemplateVars,
    SMSTemplateVars,
    User,
)


async def create_code(
    tenant_id: str,
    email: Union[None, str] = None,
    phone_number: Union[None, str] = None,
    user_input_code: Union[None, str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> CreateCodeOkResult:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.create_code(
        email=email,
        phone_number=phone_number,
        user_input_code=user_input_code,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def create_new_code_for_device(
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
    return await PasswordlessRecipe.get_instance().recipe_implementation.create_new_code_for_device(
        device_id=device_id,
        user_input_code=user_input_code,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def consume_code(
    tenant_id: str,
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
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.consume_code(
        pre_auth_session_id=pre_auth_session_id,
        user_input_code=user_input_code,
        device_id=device_id,
        link_code=link_code,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def get_user_by_id(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.get_user_by_id(
        user_id=user_id, user_context=user_context
    )


async def get_user_by_email(
    tenant_id: str, email: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    if user_context is None:
        user_context = {}
    return (
        await PasswordlessRecipe.get_instance().recipe_implementation.get_user_by_email(
            email=email,
            tenant_id=tenant_id,
            user_context=user_context,
        )
    )


async def get_user_by_phone_number(
    tenant_id: str, phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.get_user_by_phone_number(
        phone_number=phone_number,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def update_user(
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
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.update_user(
        user_id=user_id,
        email=email,
        phone_number=phone_number,
        user_context=user_context,
    )


async def delete_email_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.delete_email_for_user(
        user_id=user_id, user_context=user_context
    )


async def delete_phone_number_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.delete_phone_number_for_user(
        user_id=user_id, user_context=user_context
    )


async def revoke_all_codes(
    tenant_id: str,
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> RevokeAllCodesOkResult:
    if user_context is None:
        user_context = {}
    return (
        await PasswordlessRecipe.get_instance().recipe_implementation.revoke_all_codes(
            email=email,
            phone_number=phone_number,
            tenant_id=tenant_id,
            user_context=user_context,
        )
    )


async def revoke_code(
    tenant_id: str, code_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> RevokeCodeOkResult:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.revoke_code(
        tenant_id=tenant_id,
        code_id=code_id,
        user_context=user_context,
    )


async def list_codes_by_email(
    tenant_id: str, email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[DeviceType]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_email(
        email=email, tenant_id=tenant_id, user_context=user_context
    )


async def list_codes_by_phone_number(
    tenant_id: str, phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[DeviceType]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_phone_number(
        phone_number=phone_number,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def list_codes_by_device_id(
    tenant_id: str, device_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeviceType, None]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_device_id(
        device_id=device_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def list_codes_by_pre_auth_session_id(
    tenant_id: str,
    pre_auth_session_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[DeviceType, None]:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_pre_auth_session_id(
        pre_auth_session_id=pre_auth_session_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def create_magic_link(
    tenant_id: str,
    email: Union[str, None],
    phone_number: Union[str, None],
    user_context: Union[None, Dict[str, Any]] = None,
) -> str:
    if user_context is None:
        user_context = {}
    request = get_request_from_user_context(user_context)
    return await PasswordlessRecipe.get_instance().create_magic_link(
        email=email,
        phone_number=phone_number,
        tenant_id=tenant_id,
        request=request,
        user_context=user_context,
    )


async def signinup(
    tenant_id: str,
    email: Union[str, None],
    phone_number: Union[str, None],
    user_context: Union[None, Dict[str, Any]] = None,
) -> ConsumeCodeOkResult:
    if user_context is None:
        user_context = {}
    return await PasswordlessRecipe.get_instance().signinup(
        email=email,
        phone_number=phone_number,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def send_email(
    input_: EmailTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    return await PasswordlessRecipe.get_instance().email_delivery.ingredient_interface_impl.send_email(
        input_, user_context
    )


async def send_sms(
    input_: SMSTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    return await PasswordlessRecipe.get_instance().sms_delivery.ingredient_interface_impl.send_sms(
        input_, user_context
    )
