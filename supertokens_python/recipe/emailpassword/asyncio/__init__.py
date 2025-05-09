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
from typing import Any, Dict, Optional, Union

from typing_extensions import Literal

from supertokens_python import get_request_from_user_context
from supertokens_python.asyncio import get_user
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.interfaces import (
    ConsumePasswordResetTokenOkResult,
    CreateResetPasswordOkResult,
    EmailAlreadyExistsError,
    PasswordPolicyViolationError,
    PasswordResetTokenInvalidError,
    SignInOkResult,
    SignUpOkResult,
    UnknownUserIdError,
    UpdateEmailOrPasswordEmailChangeNotAllowedError,
    UpdateEmailOrPasswordOkResult,
    WrongCredentialsError,
)
from supertokens_python.recipe.emailpassword.types import (
    PasswordResetEmailTemplateVars,
    PasswordResetEmailTemplateVarsUser,
)
from supertokens_python.recipe.emailpassword.utils import get_password_reset_link
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError

from ....types import RecipeUserId
from ...multitenancy.constants import DEFAULT_TENANT_ID
from ..types import EmailTemplateVars


async def sign_up(
    tenant_id: str,
    email: str,
    password: str,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[SignUpOkResult, EmailAlreadyExistsError, LinkingToSessionUserFailedError]:
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.sign_up(
        email=email,
        password=password,
        tenant_id=tenant_id or DEFAULT_TENANT_ID,
        session=session,
        user_context=user_context,
        should_try_linking_with_session_user=session is not None,
    )


async def sign_in(
    tenant_id: str,
    email: str,
    password: str,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[SignInOkResult, WrongCredentialsError, LinkingToSessionUserFailedError]:
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.sign_in(
        email=email,
        password=password,
        tenant_id=tenant_id or DEFAULT_TENANT_ID,
        session=session,
        user_context=user_context,
        should_try_linking_with_session_user=session is not None,
    )


async def verify_credentials(
    tenant_id: str,
    email: str,
    password: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[SignInOkResult, WrongCredentialsError]:
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.verify_credentials(
        email, password, tenant_id or DEFAULT_TENANT_ID, user_context
    )


async def create_reset_password_token(
    tenant_id: str,
    user_id: str,
    email: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[CreateResetPasswordOkResult, UnknownUserIdError]:
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.create_reset_password_token(
        user_id, email, tenant_id or DEFAULT_TENANT_ID, user_context
    )


async def reset_password_using_token(
    tenant_id: str,
    token: str,
    new_password: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    UpdateEmailOrPasswordOkResult,
    PasswordPolicyViolationError,
    PasswordResetTokenInvalidError,
    UnknownUserIdError,
]:
    if user_context is None:
        user_context = {}
    consume_resp = await consume_password_reset_token(tenant_id, token, user_context)
    if not isinstance(consume_resp, ConsumePasswordResetTokenOkResult):
        return consume_resp

    result = await update_email_or_password(
        recipe_user_id=RecipeUserId(consume_resp.user_id),
        email=consume_resp.email,
        password=new_password,
        tenant_id_for_password_policy=tenant_id,
        user_context=user_context,
    )

    if isinstance(
        result,
        (EmailAlreadyExistsError, UpdateEmailOrPasswordEmailChangeNotAllowedError),
    ):
        raise Exception("Should never happen")

    return result


async def consume_password_reset_token(
    tenant_id: str,
    token: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[ConsumePasswordResetTokenOkResult, PasswordResetTokenInvalidError]:
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.consume_password_reset_token(
        token, tenant_id or DEFAULT_TENANT_ID, user_context
    )


async def update_email_or_password(
    recipe_user_id: RecipeUserId,
    email: Optional[str] = None,
    password: Optional[str] = None,
    apply_password_policy: Optional[bool] = None,
    tenant_id_for_password_policy: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    UpdateEmailOrPasswordOkResult,
    EmailAlreadyExistsError,
    UnknownUserIdError,
    UpdateEmailOrPasswordEmailChangeNotAllowedError,
    PasswordPolicyViolationError,
]:
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.update_email_or_password(
        recipe_user_id,
        email,
        password,
        apply_password_policy,
        tenant_id_for_password_policy or DEFAULT_TENANT_ID,
        user_context,
    )


async def create_reset_password_link(
    tenant_id: str,
    user_id: str,
    email: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[str, UnknownUserIdError]:
    if user_context is None:
        user_context = {}
    token = await create_reset_password_token(tenant_id, user_id, email, user_context)
    if isinstance(token, UnknownUserIdError):
        return token

    recipe_instance = EmailPasswordRecipe.get_instance()
    request = get_request_from_user_context(user_context)
    return get_password_reset_link(
        recipe_instance.get_app_info(),
        token.token,
        tenant_id or DEFAULT_TENANT_ID,
        request,
        user_context,
    )


async def send_reset_password_email(
    tenant_id: str,
    user_id: str,
    email: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[Literal["UNKNOWN_USER_ID_ERROR"], Literal["OK"]]:
    if user_context is None:
        user_context = {}

    user = await get_user(user_id, user_context)
    if user is None:
        return "UNKNOWN_USER_ID_ERROR"

    login_method = next(
        (
            m
            for m in user.login_methods
            if m.recipe_id == "emailpassword" and m.has_same_email_as(email)
        ),
        None,
    )
    if login_method is None:
        return "UNKNOWN_USER_ID_ERROR"

    link = await create_reset_password_link(tenant_id, user_id, email, user_context)
    if isinstance(link, UnknownUserIdError):
        return "UNKNOWN_USER_ID_ERROR"

    assert login_method.email is not None
    await send_email(
        PasswordResetEmailTemplateVars(
            user=PasswordResetEmailTemplateVarsUser(
                user_id=user.id,
                email=login_method.email,
                recipe_user_id=login_method.recipe_user_id,
            ),
            password_reset_link=link,
            tenant_id=tenant_id or DEFAULT_TENANT_ID,
        ),
        user_context,
    )

    return "OK"


async def send_email(
    input_: EmailTemplateVars,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().email_delivery.ingredient_interface_impl.send_email(
        input_, user_context
    )
