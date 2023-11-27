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
from supertokens_python import get_request_from_user_context

from supertokens_python.recipe.passwordless.interfaces import (
    DeleteUserInfoOkResult,
    DeleteUserInfoUnknownUserIdError,
)

from .. import interfaces
from ..recipe import ThirdPartyPasswordlessRecipe
from ..types import EmailTemplateVars, SMSTemplateVars, User


async def get_user_by_id(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[None, User]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.get_user_by_id(
        user_id, user_context
    )


async def get_user_by_third_party_info(
    tenant_id: str,
    third_party_id: str,
    third_party_user_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.get_user_by_thirdparty_info(
        third_party_id,
        third_party_user_id,
        tenant_id,
        user_context,
    )


async def thirdparty_manually_create_or_update_user(
    tenant_id: str,
    third_party_id: str,
    third_party_user_id: str,
    email: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.thirdparty_manually_create_or_update_user(
        third_party_id,
        third_party_user_id,
        email,
        tenant_id,
        user_context,
    )


async def thirdparty_get_provider(
    tenant_id: str,
    third_party_id: str,
    client_type: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.thirdparty_get_provider(
        third_party_id, client_type, tenant_id, user_context
    )


async def get_users_by_email(
    tenant_id: str, email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[User]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.get_users_by_email(
        email, tenant_id, user_context
    )


async def create_code(
    tenant_id: str,
    email: Union[None, str] = None,
    phone_number: Union[None, str] = None,
    user_input_code: Union[None, str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> interfaces.CreateCodeOkResult:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.create_code(
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
    interfaces.CreateNewCodeForDeviceOkResult,
    interfaces.CreateNewCodeForDeviceRestartFlowError,
    interfaces.CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.create_new_code_for_device(
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
    interfaces.ConsumeCodeOkResult,
    interfaces.ConsumeCodeIncorrectUserInputCodeError,
    interfaces.ConsumeCodeExpiredUserInputCodeError,
    interfaces.ConsumeCodeRestartFlowError,
]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.consume_code(
        pre_auth_session_id=pre_auth_session_id,
        user_input_code=user_input_code,
        device_id=device_id,
        link_code=link_code,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def get_user_by_phone_number(
    tenant_id: str, phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.get_user_by_phone_number(
        phone_number=phone_number,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def update_passwordless_user(
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
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.update_passwordless_user(
        user_id=user_id,
        email=email,
        phone_number=phone_number,
        user_context=user_context,
    )


async def delete_email_for_passwordless_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.delete_email_for_passwordless_user(
        user_id=user_id, user_context=user_context
    )


async def delete_phone_number_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.delete_phone_number_for_user(
        user_id=user_id, user_context=user_context
    )


async def revoke_all_codes(
    tenant_id: str,
    email: Union[str, None] = None,
    phone_number: Union[str, None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> interfaces.RevokeAllCodesOkResult:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.revoke_all_codes(
        email=email,
        phone_number=phone_number,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def revoke_code(
    tenant_id: str, code_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> interfaces.RevokeCodeOkResult:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.revoke_code(
        code_id=code_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def list_codes_by_email(
    tenant_id: str, email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[interfaces.DeviceType]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_email(
        email=email, tenant_id=tenant_id, user_context=user_context
    )


async def list_codes_by_phone_number(
    tenant_id: str, phone_number: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[interfaces.DeviceType]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_phone_number(
        phone_number=phone_number,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def list_codes_by_device_id(
    tenant_id: str, device_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[interfaces.DeviceType, None]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_device_id(
        device_id=device_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def list_codes_by_pre_auth_session_id(
    tenant_id: str,
    pre_auth_session_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[interfaces.DeviceType, None]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyPasswordlessRecipe.get_instance().recipe_implementation.list_codes_by_pre_auth_session_id(
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
    return await ThirdPartyPasswordlessRecipe.get_instance().passwordless_recipe.create_magic_link(
        tenant_id=tenant_id,
        email=email,
        phone_number=phone_number,
        request=request,
        user_context=user_context,
    )


async def passwordless_signinup(
    tenant_id: str,
    email: Union[str, None],
    phone_number: Union[str, None],
    user_context: Union[None, Dict[str, Any]] = None,
) -> interfaces.ConsumeCodeOkResult:
    if user_context is None:
        user_context = {}
    result = (
        await ThirdPartyPasswordlessRecipe.get_instance().passwordless_recipe.signinup(
            tenant_id=tenant_id,
            email=email,
            phone_number=phone_number,
            user_context=user_context,
        )
    )
    return interfaces.ConsumeCodeOkResult(
        result.created_new_user,
        User(
            result.user.user_id,
            result.user.email,
            result.user.phone_number,
            result.user.time_joined,
            result.user.tenant_ids,
            None,
        ),
    )


async def send_email(
    input_: EmailTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    return await ThirdPartyPasswordlessRecipe.get_instance().email_delivery.ingredient_interface_impl.send_email(
        input_, user_context
    )


async def send_sms(
    input_: SMSTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    return await ThirdPartyPasswordlessRecipe.get_instance().sms_delivery.ingredient_interface_impl.send_sms(
        input_, user_context
    )
