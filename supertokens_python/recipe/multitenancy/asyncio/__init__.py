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

from supertokens_python.recipe.emailverification.interfaces import (
    GetEmailForUserIdOkResult,
    EmailDoesNotExistError,
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    UnverifyEmailOkResult,
    CreateEmailVerificationTokenOkResult,
    RevokeEmailVerificationTokensOkResult,
)
from supertokens_python.recipe.emailverification.types import EmailTemplateVars
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe


async def create_email_verification_token(
    user_id: str,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    CreateEmailVerificationTokenOkResult,
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
]:
    if user_context is None:
        user_context = {}
    recipe = EmailVerificationRecipe.get_instance()
    if email is None:
        email_info = await recipe.get_email_for_user_id(user_id, user_context)
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            return CreateEmailVerificationTokenEmailAlreadyVerifiedError()
        else:
            raise Exception("Unknown User ID provided without email")

    return await recipe.recipe_implementation.create_email_verification_token(
        user_id, email, user_context
    )


async def verify_email_using_token(
    token: str, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    return await EmailVerificationRecipe.get_instance().recipe_implementation.verify_email_using_token(
        token, user_context
    )


async def is_email_verified(
    user_id: str,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    recipe = EmailVerificationRecipe.get_instance()
    if email is None:
        email_info = await recipe.get_email_for_user_id(user_id, user_context)
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            return True
        else:
            raise Exception("Unknown User ID provided without email")

    return await recipe.recipe_implementation.is_email_verified(
        user_id, email, user_context
    )


async def revoke_email_verification_tokens(
    user_id: str,
    email: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> RevokeEmailVerificationTokensOkResult:
    if user_context is None:
        user_context = {}

    recipe = EmailVerificationRecipe.get_instance()
    if email is None:
        email_info = await recipe.get_email_for_user_id(user_id, user_context)
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            return RevokeEmailVerificationTokensOkResult()
        else:
            raise Exception("Unknown User ID provided without email")

    return await EmailVerificationRecipe.get_instance().recipe_implementation.revoke_email_verification_tokens(
        user_id, email, user_context
    )


async def unverify_email(
    user_id: str,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    recipe = EmailVerificationRecipe.get_instance()
    if email is None:
        email_info = await recipe.get_email_for_user_id(user_id, user_context)
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            # Here we are returning OK since that's how it used to work, but a later call
            # to is_verified will still return true
            return UnverifyEmailOkResult
        else:
            raise Exception("Unknown User ID provided without email")

    return await EmailVerificationRecipe.get_instance().recipe_implementation.unverify_email(
        user_id, email, user_context
    )


async def send_email(
    input_: EmailTemplateVars, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    return await EmailVerificationRecipe.get_instance().email_delivery.ingredient_interface_impl.send_email(
        input_, user_context
    )
