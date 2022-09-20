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

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.emailverification.types import EmailTemplateVars


def create_email_verification_token(
    user_id: str,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailverification.asyncio import (
        create_email_verification_token,
    )

    return sync(create_email_verification_token(user_id, email, user_context))


def verify_email_using_token(
    token: str, user_context: Union[None, Dict[str, Any]] = None
):
    from supertokens_python.recipe.emailverification.asyncio import (
        verify_email_using_token,
    )

    return sync(verify_email_using_token(token, user_context))


def is_email_verified(
    user_id: str,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailverification.asyncio import is_email_verified

    return sync(is_email_verified(user_id, email, user_context))


def revoke_email_verification_tokens(
    user_id: str,
    email: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailverification.asyncio import (
        revoke_email_verification_tokens,
    )

    return sync(revoke_email_verification_tokens(user_id, email, user_context))


def unverify_email(
    user_id: str,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.emailverification.asyncio import unverify_email

    return sync(unverify_email(user_id, email, user_context))


def send_email(
    input_: EmailTemplateVars, user_context: Union[None, Dict[str, Any]] = None
):
    from supertokens_python.recipe.emailverification.asyncio import send_email

    return sync(send_email(input_, user_context))
