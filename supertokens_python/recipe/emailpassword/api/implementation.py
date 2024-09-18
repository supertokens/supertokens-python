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
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import (
    SignInNotAllowedResponse,
    SignUpNotAllowedResponse,
    get_authenticating_user_and_add_to_current_tenant_if_required,
    is_fake_email,
    post_auth_checks,
    pre_auth_checks,
)

from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.accountlinking import (
    AccountInfoWithRecipeIdAndUserId,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.emailpassword.constants import (
    FORM_FIELD_EMAIL_ID,
    FORM_FIELD_PASSWORD_ID,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface,
    CreateResetPasswordOkResult,
    EmailAlreadyExistsError,
    EmailExistsGetOkResult,
    GeneratePasswordResetTokenPostNotAllowedResponse,
    GeneratePasswordResetTokenPostOkResult,
    LinkingToSessionUserFailedError,
    PasswordPolicyViolationError,
    PasswordResetPostOkResult,
    PasswordResetTokenInvalidError,
    SignInOkResult,
    SignInPostNotAllowedResponse,
    SignInPostOkResult,
    SignUpOkResult,
    SignUpPostNotAllowedResponse,
    SignUpPostOkResult,
    UpdateEmailOrPasswordEmailChangeNotAllowedError,
    WrongCredentialsError,
)
from supertokens_python.recipe.emailpassword.types import (
    EmailTemplateVars,
    FormField,
    PasswordResetEmailTemplateVarsUser,
)
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.totp.types import UnknownUserIdError
from ..utils import get_password_reset_link

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.interfaces import APIOptions

from supertokens_python.types import AccountInfo, GeneralErrorResponse, RecipeUserId


class APIImplementation(APIInterface):
    async def email_exists_get(
        self,
        email: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailExistsGetOkResult, GeneralErrorResponse]:
        # Check if there exists an email password user with the same email
        users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfo(email=email),
            do_union_of_account_info=False,
            user_context=user_context,
        )

        email_password_user_exists = any(
            any(
                lm.recipe_id == "emailpassword" and lm.has_same_email_as(email)
                for lm in user.login_methods
            )
            for user in users
        )

        return EmailExistsGetOkResult(exists=email_password_user_exists)

    async def generate_password_reset_token_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        GeneratePasswordResetTokenPostOkResult,
        GeneratePasswordResetTokenPostNotAllowedResponse,
        GeneralErrorResponse,
    ]:
        email = next(f.value for f in form_fields if f.id == "email")

        async def generate_and_send_password_reset_token(
            primary_user_id: str, recipe_user_id: Optional[RecipeUserId]
        ) -> Union[
            GeneratePasswordResetTokenPostOkResult,
            GeneratePasswordResetTokenPostNotAllowedResponse,
            GeneralErrorResponse,
        ]:
            user_id = (
                recipe_user_id.get_as_string() if recipe_user_id else primary_user_id
            )
            response = (
                await api_options.recipe_implementation.create_reset_password_token(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    email=email,
                    user_context=user_context,
                )
            )
            if isinstance(response, UnknownUserIdError):
                log_debug_message(
                    f"Password reset email not sent, unknown user id: {user_id}"
                )
                return GeneratePasswordResetTokenPostOkResult()

            assert isinstance(response, CreateResetPasswordOkResult)
            password_reset_link = get_password_reset_link(
                app_info=api_options.app_info,
                token=response.token,
                tenant_id=tenant_id,
                request=api_options.request,
                user_context=user_context,
            )

            log_debug_message(f"Sending password reset email to {email}")
            await api_options.email_delivery.ingredient_interface_impl.send_email(
                EmailTemplateVars(
                    user=PasswordResetEmailTemplateVarsUser(
                        user_id=primary_user_id,
                        recipe_user_id=recipe_user_id,
                        email=email,
                    ),
                    password_reset_link=password_reset_link,
                    tenant_id=tenant_id,
                ),
                user_context=user_context,
            )

            return GeneratePasswordResetTokenPostOkResult()

        users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfo(email=email),
            do_union_of_account_info=False,
            user_context=user_context,
        )

        email_password_account = next(
            (
                lm
                for user in users
                for lm in user.login_methods
                if lm.recipe_id == "emailpassword" and lm.has_same_email_as(email)
            ),
            None,
        )

        primary_user_associated_with_email = next(
            (u for u in users if u.is_primary_user), None
        )

        if primary_user_associated_with_email is None:
            if email_password_account is None:
                log_debug_message(
                    f"Password reset email not sent, unknown user email: {email}"
                )
                return GeneratePasswordResetTokenPostOkResult()
            return await generate_and_send_password_reset_token(
                email_password_account.recipe_user_id.get_as_string(),
                email_password_account.recipe_user_id,
            )

        email_verified = any(
            lm.has_same_email_as(email) and lm.verified
            for lm in primary_user_associated_with_email.login_methods
        )

        has_other_email_or_phone = any(
            (lm.email is not None and not lm.has_same_email_as(email))
            or lm.phone_number is not None
            for lm in primary_user_associated_with_email.login_methods
        )

        if not email_verified and has_other_email_or_phone:
            return GeneratePasswordResetTokenPostNotAllowedResponse(
                "Reset password link was not created because of account take over risk. Please contact support. (ERR_CODE_001)"
            )

        should_do_account_linking_response = await AccountLinkingRecipe.get_instance().config.should_do_automatic_account_linking(
            AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                email_password_account
                or AccountInfoWithRecipeId(email=email, recipe_id="emailpassword")
            ),
            primary_user_associated_with_email,
            None,
            tenant_id,
            user_context,
        )

        if email_password_account is None:
            if isinstance(
                should_do_account_linking_response, ShouldNotAutomaticallyLink
            ):
                log_debug_message(
                    "Password reset email not sent, since email password user didn't exist, and account linking not enabled"
                )
                return GeneratePasswordResetTokenPostOkResult()

            is_sign_up_allowed = (
                await AccountLinkingRecipe.get_instance().is_sign_up_allowed(
                    new_user=AccountInfoWithRecipeId(
                        email=email, recipe_id="emailpassword"
                    ),
                    is_verified=True,
                    session=None,
                    tenant_id=tenant_id,
                    user_context=user_context,
                )
            )
            if is_sign_up_allowed:
                return await generate_and_send_password_reset_token(
                    primary_user_associated_with_email.id, None
                )
            else:
                log_debug_message(
                    f"Password reset email not sent, is_sign_up_allowed returned false for email: {email}"
                )
                return GeneratePasswordResetTokenPostOkResult()

        are_the_two_accounts_linked = any(
            lm.recipe_user_id.get_as_string()
            == email_password_account.recipe_user_id.get_as_string()
            for lm in primary_user_associated_with_email.login_methods
        )

        if are_the_two_accounts_linked:
            return await generate_and_send_password_reset_token(
                primary_user_associated_with_email.id,
                email_password_account.recipe_user_id,
            )

        if isinstance(should_do_account_linking_response, ShouldNotAutomaticallyLink):
            return await generate_and_send_password_reset_token(
                email_password_account.recipe_user_id.get_as_string(),
                email_password_account.recipe_user_id,
            )

        if not should_do_account_linking_response.should_require_verification:
            return await generate_and_send_password_reset_token(
                primary_user_associated_with_email.id,
                email_password_account.recipe_user_id,
            )

        return await generate_and_send_password_reset_token(
            primary_user_associated_with_email.id, email_password_account.recipe_user_id
        )

    async def password_reset_post(
        self,
        form_fields: List[FormField],
        token: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        PasswordResetPostOkResult,
        PasswordResetTokenInvalidError,
        PasswordPolicyViolationError,
        GeneralErrorResponse,
    ]:
        async def mark_email_as_verified(recipe_user_id: RecipeUserId, email: str):
            email_verification_instance = (
                EmailVerificationRecipe.get_instance_optional()
            )
            if email_verification_instance:
                token_response = await email_verification_instance.recipe_implementation.create_email_verification_token(
                    tenant_id=tenant_id,
                    recipe_user_id=recipe_user_id,
                    email=email,
                    user_context=user_context,
                )

                if token_response.status == "OK":
                    await email_verification_instance.recipe_implementation.verify_email_using_token(
                        tenant_id=tenant_id,
                        token=token_response.token,
                        attempt_account_linking=False,
                        user_context=user_context,
                    )

        async def do_update_password_and_verify_email_and_try_link_if_not_primary(
            recipe_user_id: RecipeUserId,
        ):
            update_response = (
                await api_options.recipe_implementation.update_email_or_password(
                    tenant_id_for_password_policy=tenant_id,
                    email=None,
                    recipe_user_id=recipe_user_id,
                    password=new_password,
                    apply_password_policy=None,
                    user_context=user_context,
                )
            )

            if isinstance(
                update_response,
                (
                    EmailAlreadyExistsError,
                    UpdateEmailOrPasswordEmailChangeNotAllowedError,
                ),
            ):
                raise Exception("Should never happen")
            if isinstance(update_response, UnknownUserIdError):
                return PasswordResetTokenInvalidError()
            elif isinstance(update_response, PasswordPolicyViolationError):
                return update_response
            else:
                await mark_email_as_verified(
                    recipe_user_id, email_for_whom_token_was_generated
                )
                updated_user_after_email_verification = await get_user(
                    recipe_user_id.get_as_string(), user_context
                )
                if updated_user_after_email_verification is None:
                    raise Exception(
                        "Should never happen - user deleted after during password reset"
                    )

                if updated_user_after_email_verification.is_primary_user:
                    return PasswordResetPostOkResult(
                        user=updated_user_after_email_verification,
                        email=email_for_whom_token_was_generated,
                    )

                link_res = await AccountLinkingRecipe.get_instance().try_linking_by_account_info_or_create_primary_user(
                    tenant_id=tenant_id,
                    input_user=updated_user_after_email_verification,
                    session=None,
                    user_context=user_context,
                )
                user_after_we_tried_linking = (
                    link_res.user
                    if link_res.status == "OK"
                    else updated_user_after_email_verification
                )

                assert user_after_we_tried_linking is not None

                return PasswordResetPostOkResult(
                    user=user_after_we_tried_linking,
                    email=email_for_whom_token_was_generated,
                )

        new_password = next(f.value for f in form_fields if f.id == "password")

        token_consumption_response = (
            await api_options.recipe_implementation.consume_password_reset_token(
                token=token,
                tenant_id=tenant_id,
                user_context=user_context,
            )
        )

        if isinstance(token_consumption_response, PasswordResetTokenInvalidError):
            return PasswordResetTokenInvalidError()

        user_id_for_whom_token_was_generated = token_consumption_response.user_id
        email_for_whom_token_was_generated = token_consumption_response.email

        existing_user = await get_user(token_consumption_response.user_id, user_context)

        if existing_user is None:
            return PasswordResetTokenInvalidError()

        if existing_user.is_primary_user:
            email_password_user_is_linked_to_existing_user = any(
                lm.recipe_user_id.get_as_string()
                == user_id_for_whom_token_was_generated
                and lm.recipe_id == "emailpassword"
                for lm in existing_user.login_methods
            )

            if email_password_user_is_linked_to_existing_user:
                return await do_update_password_and_verify_email_and_try_link_if_not_primary(
                    RecipeUserId(user_id_for_whom_token_was_generated)
                )
            else:
                create_user_response = (
                    await api_options.recipe_implementation.create_new_recipe_user(
                        tenant_id=tenant_id,
                        email=token_consumption_response.email,
                        password=new_password,
                        user_context=user_context,
                    )
                )
                if isinstance(create_user_response, EmailAlreadyExistsError):
                    return PasswordResetTokenInvalidError()
                else:
                    await mark_email_as_verified(
                        create_user_response.user.login_methods[0].recipe_user_id,
                        token_consumption_response.email,
                    )
                    updated_user = await get_user(
                        create_user_response.user.id,
                        user_context,
                    )
                    if updated_user is None:
                        raise Exception(
                            "Should never happen - user deleted after during password reset"
                        )
                    create_user_response.user = updated_user
                    link_res = await AccountLinkingRecipe.get_instance().try_linking_by_account_info_or_create_primary_user(
                        tenant_id=tenant_id,
                        input_user=create_user_response.user,
                        session=None,
                        user_context=user_context,
                    )
                    user_after_linking = (
                        link_res.user
                        if link_res.status == "OK"
                        else create_user_response.user
                    )
                    assert user_after_linking is not None
                    return PasswordResetPostOkResult(
                        user=user_after_linking,
                        email=token_consumption_response.email,
                    )
        else:
            return (
                await do_update_password_and_verify_email_and_try_link_if_not_primary(
                    RecipeUserId(user_id_for_whom_token_was_generated)
                )
            )

    async def sign_in_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInPostOkResult,
        WrongCredentialsError,
        SignInPostNotAllowedResponse,
        GeneralErrorResponse,
    ]:
        error_code_map = {
            "SIGN_IN_NOT_ALLOWED": "Cannot sign in due to security reasons. Please try resetting your password, use a different login method or contact support. (ERR_CODE_008)",
            "LINKING_TO_SESSION_USER_FAILED": {
                "EMAIL_VERIFICATION_REQUIRED": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_009)",
                "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_010)",
                "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_011)",
                "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_012)",
            },
        }

        email = next(f.value for f in form_fields if f.id == FORM_FIELD_EMAIL_ID)
        password = next(f.value for f in form_fields if f.id == FORM_FIELD_PASSWORD_ID)

        recipe_id = "emailpassword"

        async def check_credentials_on_tenant(tenant_id: str) -> bool:
            verify_result = await api_options.recipe_implementation.verify_credentials(
                email=email,
                password=password,
                tenant_id=tenant_id,
                user_context=user_context,
            )
            return isinstance(verify_result, SignInOkResult)

        if is_fake_email(email) and session is None:
            return WrongCredentialsError()

        authenticating_user = (
            await get_authenticating_user_and_add_to_current_tenant_if_required(
                email=email,
                phone_number=None,
                third_party=None,
                user_context=user_context,
                recipe_id=recipe_id,
                session=session,
                tenant_id=tenant_id,
                check_credentials_on_tenant=check_credentials_on_tenant,
            )
        )

        is_verified = (
            authenticating_user is not None
            and authenticating_user.login_method is not None
            and authenticating_user.login_method.verified
        )

        if authenticating_user is None:
            return WrongCredentialsError()

        pre_auth_checks_result = await pre_auth_checks(
            authenticating_account_info=AccountInfoWithRecipeId(
                recipe_id=recipe_id,
                email=email,
            ),
            factor_ids=["emailpassword"],
            is_sign_up=False,
            authenticating_user=authenticating_user.user,
            is_verified=is_verified,
            sign_in_verifies_login_method=False,
            skip_session_user_update_in_core=False,
            tenant_id=tenant_id,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            user_context=user_context,
            session=session,
        )

        if pre_auth_checks_result.status != "OK":
            if isinstance(pre_auth_checks_result, SignUpNotAllowedResponse):
                raise Exception("Should never happen")
            if isinstance(pre_auth_checks_result, SignInNotAllowedResponse):
                reason = error_code_map["SIGN_IN_NOT_ALLOWED"]
                assert isinstance(reason, str)
                return SignInPostNotAllowedResponse(reason)

            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[pre_auth_checks_result.reason]
            return SignInPostNotAllowedResponse(reason=reason)

        if is_fake_email(email) and pre_auth_checks_result.is_first_factor:
            return WrongCredentialsError()

        sign_in_response = await api_options.recipe_implementation.sign_in(
            email=email,
            password=password,
            session=session,
            tenant_id=tenant_id,
            user_context=user_context,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if isinstance(sign_in_response, WrongCredentialsError):
            return WrongCredentialsError()
        if isinstance(sign_in_response, LinkingToSessionUserFailedError):
            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[sign_in_response.reason]
            return SignInPostNotAllowedResponse(reason=reason)

        post_auth_checks_result = await post_auth_checks(
            authenticated_user=sign_in_response.user,
            recipe_user_id=sign_in_response.recipe_user_id,
            is_sign_up=False,
            factor_id="emailpassword",
            session=session,
            tenant_id=tenant_id,
            user_context=user_context,
            request=api_options.request,
        )

        if post_auth_checks_result.status != "OK":
            reason = error_code_map["SIGN_IN_NOT_ALLOWED"]
            assert isinstance(reason, str)
            return SignInPostNotAllowedResponse(reason)

        return SignInPostOkResult(
            user=post_auth_checks_result.user,
            session=post_auth_checks_result.session,
        )

    async def sign_up_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignUpPostOkResult,
        EmailAlreadyExistsError,
        SignUpPostNotAllowedResponse,
        GeneralErrorResponse,
    ]:
        error_code_map = {
            "SIGN_UP_NOT_ALLOWED": "Cannot sign up due to security reasons. Please try logging in, use a different login method or contact support. (ERR_CODE_007)",
            "LINKING_TO_SESSION_USER_FAILED": {
                "EMAIL_VERIFICATION_REQUIRED": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_013)",
                "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_014)",
                "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_015)",
                "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_016)",
            },
        }

        email = next(f.value for f in form_fields if f.id == "email")
        password = next(f.value for f in form_fields if f.id == "password")

        pre_auth_check_res = await pre_auth_checks(
            authenticating_account_info=AccountInfoWithRecipeId(
                recipe_id="emailpassword",
                email=email,
            ),
            factor_ids=["emailpassword"],
            is_sign_up=True,
            is_verified=is_fake_email(email),
            sign_in_verifies_login_method=False,
            skip_session_user_update_in_core=False,
            authenticating_user=None,  # since this is a sign up, this is None
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if pre_auth_check_res.status == "SIGN_UP_NOT_ALLOWED":
            conflicting_users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
                tenant_id=tenant_id,
                account_info=AccountInfo(
                    email=email,
                ),
                do_union_of_account_info=False,
                user_context=user_context,
            )
            if any(
                any(
                    lm.recipe_id == "emailpassword" and lm.has_same_email_as(email)
                    for lm in u.login_methods
                )
                for u in conflicting_users
            ):
                return EmailAlreadyExistsError()

        if pre_auth_check_res.status != "OK":
            if isinstance(pre_auth_check_res, SignInNotAllowedResponse):
                raise Exception("Should never happen")
            if isinstance(pre_auth_check_res, SignUpNotAllowedResponse):
                reason = error_code_map["SIGN_UP_NOT_ALLOWED"]
                assert isinstance(reason, str)
                return SignUpPostNotAllowedResponse(reason)

            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[pre_auth_check_res.reason]
            return SignUpPostNotAllowedResponse(reason=reason)

        if is_fake_email(email) and pre_auth_check_res.is_first_factor:
            # Fake emails cannot be used as a first factor
            return EmailAlreadyExistsError()

        sign_up_response = await api_options.recipe_implementation.sign_up(
            tenant_id=tenant_id,
            email=email,
            password=password,
            session=session,
            user_context=user_context,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if isinstance(sign_up_response, EmailAlreadyExistsError):
            return sign_up_response
        if not isinstance(sign_up_response, SignUpOkResult):
            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[sign_up_response.reason]
            return SignUpPostNotAllowedResponse(reason=reason)

        post_auth_checks_res = await post_auth_checks(
            authenticated_user=sign_up_response.user,
            recipe_user_id=sign_up_response.recipe_user_id,
            is_sign_up=True,
            factor_id="emailpassword",
            session=session,
            request=api_options.request,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if post_auth_checks_res.status != "OK":
            # this will fail cause error_code_map doesn't have SIGN_IN_NOT_ALLOWED
            # but that's ok, cause it should never come here for sign up anyway.
            reason = error_code_map["SIGN_IN_NOT_ALLOWED"]
            assert isinstance(reason, str)
            return SignUpPostNotAllowedResponse(reason)

        return SignUpPostOkResult(
            user=post_auth_checks_res.user,
            session=post_auth_checks_res.session,
        )
