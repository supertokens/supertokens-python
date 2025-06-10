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

from supertokens_python.async_to_sync_wrapper import sync
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
    EmailTemplateVars,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import RecipeUserId
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError


def sign_up(
    tenant_id: str,
    email: str,
    password: str,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[SignUpOkResult, EmailAlreadyExistsError, LinkingToSessionUserFailedError]:
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import sign_up as async_sign_up

    return sync(async_sign_up(tenant_id, email, password, session, user_context))


def sign_in(
    tenant_id: str,
    email: str,
    password: str,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[SignInOkResult, WrongCredentialsError, LinkingToSessionUserFailedError]:
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import sign_in as async_sign_in

    return sync(async_sign_in(tenant_id, email, password, session, user_context))


def verify_credentials(
    tenant_id: str,
    email: str,
    password: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[SignInOkResult, WrongCredentialsError]:
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import (
        verify_credentials as async_verify_credentials,
    )

    return sync(async_verify_credentials(tenant_id, email, password, user_context))


def create_reset_password_token(
    tenant_id: str,
    user_id: str,
    email: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[CreateResetPasswordOkResult, UnknownUserIdError]:
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import (
        create_reset_password_token as async_create_reset_password_token,
    )

    return sync(
        async_create_reset_password_token(tenant_id, user_id, email, user_context)
    )


def reset_password_using_token(
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
    from supertokens_python.recipe.emailpassword.asyncio import (
        reset_password_using_token as async_reset_password_using_token,
    )

    return sync(
        async_reset_password_using_token(tenant_id, token, new_password, user_context)
    )


def consume_password_reset_token(
    tenant_id: str,
    token: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[ConsumePasswordResetTokenOkResult, PasswordResetTokenInvalidError]:
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import (
        consume_password_reset_token as async_consume_password_reset_token,
    )

    return sync(async_consume_password_reset_token(tenant_id, token, user_context))


def update_email_or_password(
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
    from supertokens_python.recipe.emailpassword.asyncio import (
        update_email_or_password as async_update_email_or_password,
    )

    return sync(
        async_update_email_or_password(
            recipe_user_id,
            email,
            password,
            apply_password_policy,
            tenant_id_for_password_policy,
            user_context,
        )
    )


def create_reset_password_link(
    tenant_id: str,
    user_id: str,
    email: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[str, UnknownUserIdError]:
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import (
        create_reset_password_link as async_create_reset_password_link,
    )

    return sync(
        async_create_reset_password_link(tenant_id, user_id, email, user_context)
    )


def send_reset_password_email(
    tenant_id: str,
    user_id: str,
    email: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[Literal["UNKNOWN_USER_ID_ERROR"], Literal["OK"]]:
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import (
        send_reset_password_email as async_send_reset_password_email,
    )

    return sync(
        async_send_reset_password_email(tenant_id, user_id, email, user_context)
    )


def send_email(
    input_: EmailTemplateVars,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    from supertokens_python.recipe.emailpassword.asyncio import (
        send_email as async_send_email,
    )

    return sync(async_send_email(input_, user_context))
