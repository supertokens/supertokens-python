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

from supertokens_python import get_request_from_user_context
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationLinkEmailAlreadyVerifiedError,
    CreateEmailVerificationLinkOkResult,
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    CreateEmailVerificationTokenOkResult,
    EmailDoesNotExistError,
    GetEmailForUserIdOkResult,
    RevokeEmailVerificationTokensOkResult,
    SendEmailVerificationEmailAlreadyVerifiedError,
    SendEmailVerificationEmailOkResult,
    UnverifyEmailOkResult,
)
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe
from supertokens_python.recipe.emailverification.types import (
    EmailTemplateVars,
    VerificationEmailTemplateVars,
    VerificationEmailTemplateVarsUser,
)
from supertokens_python.recipe.emailverification.utils import get_email_verify_link
from supertokens_python.types import RecipeUserId


async def create_email_verification_token(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    CreateEmailVerificationTokenOkResult,
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
]:
    if user_context is None:
        user_context = {}
    recipe = EmailVerificationRecipe.get_instance_or_throw()
    if email is None:
        email_info = await recipe.get_email_for_recipe_user_id(
            None, recipe_user_id, user_context
        )
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            return CreateEmailVerificationTokenEmailAlreadyVerifiedError()
        else:
            raise Exception("Unknown User ID provided without email")

    return await recipe.recipe_implementation.create_email_verification_token(
        recipe_user_id, email, tenant_id, user_context
    )


async def verify_email_using_token(
    tenant_id: str,
    token: str,
    attempt_account_linking: bool = True,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await EmailVerificationRecipe.get_instance_or_throw().recipe_implementation.verify_email_using_token(
        token, tenant_id, attempt_account_linking, user_context
    )


async def is_email_verified(
    recipe_user_id: RecipeUserId,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    recipe = EmailVerificationRecipe.get_instance_or_throw()
    if email is None:
        email_info = await recipe.get_email_for_recipe_user_id(
            None, recipe_user_id, user_context
        )
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            return True
        else:
            raise Exception("Unknown User ID provided without email")

    return await recipe.recipe_implementation.is_email_verified(
        recipe_user_id, email, user_context
    )


async def revoke_email_verification_tokens(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    email: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> RevokeEmailVerificationTokensOkResult:
    if user_context is None:
        user_context = {}

    recipe = EmailVerificationRecipe.get_instance_or_throw()
    if email is None:
        email_info = await recipe.get_email_for_recipe_user_id(
            None, recipe_user_id, user_context
        )
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            return RevokeEmailVerificationTokensOkResult()
        else:
            raise Exception("Unknown User ID provided without email")

    return await EmailVerificationRecipe.get_instance_or_throw().recipe_implementation.revoke_email_verification_tokens(
        recipe_user_id, email, tenant_id, user_context
    )


async def unverify_email(
    recipe_user_id: RecipeUserId,
    email: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    recipe = EmailVerificationRecipe.get_instance_or_throw()
    if email is None:
        email_info = await recipe.get_email_for_recipe_user_id(
            None, recipe_user_id, user_context
        )
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            # Here we are returning OK since that's how it used to work, but a later call
            # to is_verified will still return true
            return UnverifyEmailOkResult
        else:
            raise Exception("Unknown User ID provided without email")

    return await EmailVerificationRecipe.get_instance_or_throw().recipe_implementation.unverify_email(
        recipe_user_id, email, user_context
    )


async def send_email(
    input_: EmailTemplateVars,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await EmailVerificationRecipe.get_instance_or_throw().email_delivery.ingredient_interface_impl.send_email(
        input_, user_context
    )


async def create_email_verification_link(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    email: Optional[str],
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    CreateEmailVerificationLinkOkResult,
    CreateEmailVerificationLinkEmailAlreadyVerifiedError,
]:
    if user_context is None:
        user_context = {}

    recipe_instance = EmailVerificationRecipe.get_instance_or_throw()
    app_info = recipe_instance.get_app_info()

    email_verification_token = await create_email_verification_token(
        tenant_id, recipe_user_id, email, user_context
    )
    if isinstance(
        email_verification_token, CreateEmailVerificationTokenEmailAlreadyVerifiedError
    ):
        return CreateEmailVerificationLinkEmailAlreadyVerifiedError()

    request = get_request_from_user_context(user_context)
    return CreateEmailVerificationLinkOkResult(
        link=get_email_verify_link(
            app_info,
            email_verification_token.token,
            tenant_id,
            request,
            user_context,
        )
    )


async def send_email_verification_email(
    tenant_id: str,
    user_id: str,
    recipe_user_id: RecipeUserId,
    email: Optional[str],
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    SendEmailVerificationEmailOkResult,
    SendEmailVerificationEmailAlreadyVerifiedError,
]:
    if user_context is None:
        user_context = {}

    if email is None:
        recipe_instance = EmailVerificationRecipe.get_instance_or_throw()

        email_info = await recipe_instance.get_email_for_recipe_user_id(
            None, recipe_user_id, user_context
        )
        if isinstance(email_info, GetEmailForUserIdOkResult):
            email = email_info.email
        elif isinstance(email_info, EmailDoesNotExistError):
            return SendEmailVerificationEmailAlreadyVerifiedError()
        else:
            raise Exception("Unknown User ID provided without email")

    email_verification_link = await create_email_verification_link(
        tenant_id, recipe_user_id, email, user_context
    )

    if isinstance(
        email_verification_link, CreateEmailVerificationLinkEmailAlreadyVerifiedError
    ):
        return SendEmailVerificationEmailAlreadyVerifiedError()

    await send_email(
        VerificationEmailTemplateVars(
            user=VerificationEmailTemplateVarsUser(user_id, recipe_user_id, email),
            email_verify_link=email_verification_link.link,
            tenant_id=tenant_id,
        ),
        user_context,
    )

    return SendEmailVerificationEmailOkResult()
