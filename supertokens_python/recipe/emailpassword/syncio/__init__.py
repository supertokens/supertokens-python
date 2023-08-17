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
from typing import Any, Dict, Union, Optional

from supertokens_python.async_to_sync_wrapper import sync

from ..interfaces import SignInOkResult, SignInWrongCredentialsError
from ..types import EmailTemplateVars, User


def update_email_or_password(
    user_id: str,
    email: Union[str, None] = None,
    password: Union[str, None] = None,
    apply_password_policy: Union[bool, None] = None,
    tenant_id_for_password_policy: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailpassword.asyncio import update_email_or_password

    return sync(
        update_email_or_password(
            user_id,
            email,
            password,
            apply_password_policy,
            tenant_id_for_password_policy,
            user_context,
        )
    )


def get_user_by_id(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[None, User]:
    from supertokens_python.recipe.emailpassword.asyncio import get_user_by_id

    return sync(get_user_by_id(user_id, user_context))


def get_user_by_email(
    tenant_id: str,
    email: str,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[None, User]:
    from supertokens_python.recipe.emailpassword.asyncio import get_user_by_email

    return sync(get_user_by_email(tenant_id, email, user_context))


def create_reset_password_token(
    tenant_id: str,
    user_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailpassword.asyncio import (
        create_reset_password_token,
    )

    return sync(create_reset_password_token(tenant_id, user_id, user_context))


def reset_password_using_token(
    tenant_id: str,
    token: str,
    new_password: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailpassword.asyncio import (
        reset_password_using_token,
    )

    return sync(
        reset_password_using_token(tenant_id, token, new_password, user_context)
    )


def sign_in(
    tenant_id: str,
    email: str,
    password: str,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SignInOkResult, SignInWrongCredentialsError]:
    from supertokens_python.recipe.emailpassword.asyncio import sign_in

    return sync(sign_in(tenant_id, email, password, user_context))


def sign_up(
    tenant_id: str,
    email: str,
    password: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailpassword.asyncio import sign_up

    return sync(sign_up(tenant_id, email, password, user_context))


def send_email(
    input_: EmailTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailpassword.asyncio import send_email

    return sync(send_email(input_, user_context))


def create_reset_password_link(
    tenant_id: str,
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailpassword.asyncio import (
        create_reset_password_link,
    )

    return sync(create_reset_password_link(tenant_id, user_id, user_context))


def send_reset_password_email(
    tenant_id: str,
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailpassword.asyncio import (
        send_reset_password_email,
    )

    return sync(send_reset_password_email(tenant_id, user_id, user_context))
