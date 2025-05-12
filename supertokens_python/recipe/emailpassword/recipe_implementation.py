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

from typing import TYPE_CHECKING, Any, Dict, Union

from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import (
    link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info,
)
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import RecipeUserId
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError

from ...types import User
from .constants import FORM_FIELD_PASSWORD_ID
from .interfaces import (
    ConsumePasswordResetTokenOkResult,
    CreateResetPasswordOkResult,
    EmailAlreadyExistsError,
    PasswordPolicyViolationError,
    PasswordResetTokenInvalidError,
    RecipeInterface,
    SignInOkResult,
    SignUpOkResult,
    UnknownUserIdError,
    UpdateEmailOrPasswordEmailChangeNotAllowedError,
    UpdateEmailOrPasswordOkResult,
    WrongCredentialsError,
)
from .utils import EmailPasswordConfig

if TYPE_CHECKING:
    from supertokens_python.querier import Querier


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        ep_config: EmailPasswordConfig,
    ):
        super().__init__()
        self.querier = querier
        self.ep_config = ep_config

    async def sign_up(
        self,
        email: str,
        password: str,
        tenant_id: str,
        session: Union[SessionContainer, None],
        should_try_linking_with_session_user: Union[bool, None],
        user_context: Dict[str, Any],
    ) -> Union[
        SignUpOkResult, EmailAlreadyExistsError, LinkingToSessionUserFailedError
    ]:
        response = await self.create_new_recipe_user(
            email=email,
            password=password,
            tenant_id=tenant_id,
            user_context=user_context,
        )
        if isinstance(response, EmailAlreadyExistsError):
            return response

        updated_user = response.user

        link_result = await link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
            tenant_id=tenant_id,
            input_user=response.user,
            recipe_user_id=response.recipe_user_id,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            user_context=user_context,
        )

        if isinstance(link_result, LinkingToSessionUserFailedError):
            return LinkingToSessionUserFailedError(reason=link_result.reason)

        updated_user = link_result.user

        return SignUpOkResult(
            user=updated_user,
            recipe_user_id=response.recipe_user_id,
        )

    async def create_new_recipe_user(
        self,
        email: str,
        password: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[SignUpOkResult, EmailAlreadyExistsError]:
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signup"),
            {
                "email": email,
                "password": password,
            },
            user_context=user_context,
        )
        if response["status"] == "OK":
            return SignUpOkResult(
                user=User.from_json(response["user"]),
                recipe_user_id=RecipeUserId(response["recipeUserId"]),
            )
        return EmailAlreadyExistsError()

    async def sign_in(
        self,
        email: str,
        password: str,
        tenant_id: str,
        session: Union[SessionContainer, None],
        should_try_linking_with_session_user: Union[bool, None],
        user_context: Dict[str, Any],
    ) -> Union[SignInOkResult, WrongCredentialsError, LinkingToSessionUserFailedError]:
        response = await self.verify_credentials(
            email, password, tenant_id, user_context
        )

        if isinstance(response, SignInOkResult):
            login_method = next(
                (
                    lm
                    for lm in response.user.login_methods
                    if lm.recipe_user_id.get_as_string()
                    == response.recipe_user_id.get_as_string()
                ),
                None,
            )

            assert login_method is not None

            if not login_method.verified:
                await AccountLinkingRecipe.get_instance().verify_email_for_recipe_user_if_linked_accounts_are_verified(
                    user=response.user,
                    recipe_user_id=response.recipe_user_id,
                    user_context=user_context,
                )

                # We do this to get the updated user (in case the above function updated the verification status)
                updated_user = await get_user(
                    response.recipe_user_id.get_as_string(), user_context
                )
                assert updated_user is not None
                response.user = updated_user

            link_result = await link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
                tenant_id=tenant_id,
                input_user=response.user,
                recipe_user_id=response.recipe_user_id,
                session=session,
                should_try_linking_with_session_user=should_try_linking_with_session_user,
                user_context=user_context,
            )

            if isinstance(link_result, LinkingToSessionUserFailedError):
                return link_result

            response.user = link_result.user

        return response

    async def verify_credentials(
        self,
        email: str,
        password: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[SignInOkResult, WrongCredentialsError]:
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signin"),
            {
                "email": email,
                "password": password,
            },
            user_context=user_context,
        )

        if response["status"] == "OK":
            return SignInOkResult(
                user=User.from_json(response["user"]),
                recipe_user_id=RecipeUserId(response["recipeUserId"]),
            )

        return WrongCredentialsError()

    async def create_reset_password_token(
        self, user_id: str, email: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[CreateResetPasswordOkResult, UnknownUserIdError]:
        data = {"userId": user_id, "email": email}
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/user/password/reset/token"),
            data,
            user_context=user_context,
        )
        if "status" in response and response["status"] == "OK":
            return CreateResetPasswordOkResult(response["token"])
        return UnknownUserIdError()

    async def consume_password_reset_token(
        self,
        token: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[ConsumePasswordResetTokenOkResult, PasswordResetTokenInvalidError]:
        data = {"token": token}
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/user/password/reset/token/consume"),
            data,
            user_context=user_context,
        )
        if "status" not in response or response["status"] != "OK":
            return PasswordResetTokenInvalidError()
        return ConsumePasswordResetTokenOkResult(response["email"], response["userId"])

    async def update_email_or_password(
        self,
        recipe_user_id: RecipeUserId,
        email: Union[str, None],
        password: Union[str, None],
        apply_password_policy: Union[bool, None],
        tenant_id_for_password_policy: str,
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateEmailOrPasswordOkResult,
        EmailAlreadyExistsError,
        UnknownUserIdError,
        PasswordPolicyViolationError,
        UpdateEmailOrPasswordEmailChangeNotAllowedError,
    ]:
        account_linking = AccountLinkingRecipe.get_instance()
        data = {"recipeUserId": recipe_user_id.get_as_string()}

        if email is not None:
            user = await get_user(recipe_user_id.get_as_string(), user_context)
            if user is None:
                return UnknownUserIdError()

            ev_instance = EmailVerificationRecipe.get_instance_optional()
            is_email_verified = False
            if ev_instance:
                is_email_verified = (
                    await ev_instance.recipe_implementation.is_email_verified(
                        recipe_user_id=recipe_user_id,
                        email=email,
                        user_context=user_context,
                    )
                )

            is_email_change_allowed = await account_linking.is_email_change_allowed(
                user=user,
                is_verified=is_email_verified,
                new_email=email,
                session=None,
                user_context=user_context,
            )
            if not is_email_change_allowed.allowed:
                reason = (
                    "New email cannot be applied to existing account because of account takeover risks."
                    if is_email_change_allowed.reason == "ACCOUNT_TAKEOVER_RISK"
                    else "New email cannot be applied to existing account because of there is another primary user with the same email address."
                )
                return UpdateEmailOrPasswordEmailChangeNotAllowedError(reason)

            data["email"] = email

        if password is not None:
            if apply_password_policy is None or apply_password_policy:
                form_fields = self.ep_config.sign_up_feature.form_fields
                password_field = next(
                    field for field in form_fields if field.id == FORM_FIELD_PASSWORD_ID
                )
                error = await password_field.validate(
                    password, tenant_id_for_password_policy
                )
                if error is not None:
                    return PasswordPolicyViolationError(error)
            data["password"] = password

        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user"),
            data,
            None,
            user_context=user_context,
        )

        if response.get("status") == "OK":
            user = await get_user(recipe_user_id.get_as_string(), user_context)
            if user is None:
                return UnknownUserIdError()
            await AccountLinkingRecipe.get_instance().verify_email_for_recipe_user_if_linked_accounts_are_verified(
                user=user,
                recipe_user_id=recipe_user_id,
                user_context=user_context,
            )
            return UpdateEmailOrPasswordOkResult()
        elif response.get("status") == "EMAIL_ALREADY_EXISTS_ERROR":
            return EmailAlreadyExistsError()
        else:
            return UnknownUserIdError()
