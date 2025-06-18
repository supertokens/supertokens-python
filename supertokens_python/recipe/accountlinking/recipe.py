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

from os import environ
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.logger import (
    log_debug_message,
)
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.process_state import PROCESS_STATE, ProcessState
from supertokens_python.querier import Querier
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.supertokens import Supertokens
from supertokens_python.types.base import AccountInfoInput

from .interfaces import RecipeInterface
from .recipe_implementation import RecipeImplementation
from .types import (
    AccountInfoWithRecipeId,
    AccountInfoWithRecipeIdAndUserId,
    InputOverrideConfig,
    RecipeLevelUser,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)
from .utils import validate_and_normalise_user_input

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.emailverification.recipe import (
        EmailVerificationRecipe,
    )
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.types import LoginMethod, RecipeUserId, User


class EmailChangeAllowedResult:
    def __init__(
        self,
        allowed: bool,
        reason: Literal["OK", "PRIMARY_USER_CONFLICT", "ACCOUNT_TAKEOVER_RISK"],
    ):
        self.allowed = allowed
        self.reason: Literal["OK", "PRIMARY_USER_CONFLICT", "ACCOUNT_TAKEOVER_RISK"] = (
            reason
        )


class TryLinkingByAccountInfoOrCreatePrimaryUserResult:
    def __init__(self, status: Literal["OK", "NO_LINK"], user: Optional[User]):
        self.status: Literal["OK", "NO_LINK"] = status
        self.user = user


class AccountLinkingRecipe(RecipeModule):
    recipe_id = "accountlinking"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        on_account_linked: Optional[
            Callable[[User, RecipeLevelUser, Dict[str, Any]], Awaitable[None]]
        ] = None,
        should_do_automatic_account_linking: Optional[
            Callable[
                [
                    AccountInfoWithRecipeIdAndUserId,
                    Optional[User],
                    Optional[SessionContainer],
                    str,
                    Dict[str, Any],
                ],
                Awaitable[Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]],
            ]
        ] = None,
        override: Optional[InputOverrideConfig] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            app_info, on_account_linked, should_do_automatic_account_linking, override
        )
        recipe_implementation: RecipeInterface = RecipeImplementation(
            Querier.get_instance(recipe_id), self, self.config
        )

        self.recipe_implementation: RecipeInterface = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        self.email_verification_recipe: EmailVerificationRecipe | None = None

    def register_email_verification_recipe(
        self, email_verification_recipe: EmailVerificationRecipe
    ):
        self.email_verification_recipe = email_verification_recipe

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return False

    def get_apis_handled(self) -> List[APIHandled]:
        return []

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: Optional[str],
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Union[BaseResponse, None]:
        raise Exception("Should never come here")

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(
        on_account_linked: Optional[
            Callable[[User, RecipeLevelUser, Dict[str, Any]], Awaitable[None]]
        ] = None,
        should_do_automatic_account_linking: Optional[
            Callable[
                [
                    AccountInfoWithRecipeIdAndUserId,
                    Optional[User],
                    Optional[SessionContainer],
                    str,
                    Dict[str, Any],
                ],
                Awaitable[Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]],
            ]
        ] = None,
        override: Optional[InputOverrideConfig] = None,
    ):
        def func(app_info: AppInfo):
            if AccountLinkingRecipe.__instance is None:
                AccountLinkingRecipe.__instance = AccountLinkingRecipe(
                    AccountLinkingRecipe.recipe_id,
                    app_info,
                    on_account_linked,
                    should_do_automatic_account_linking,
                    override,
                )
                return AccountLinkingRecipe.__instance
            raise Exception(
                None,
                "Accountlinking recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def get_instance() -> AccountLinkingRecipe:
        if AccountLinkingRecipe.__instance is None:
            AccountLinkingRecipe.init()(Supertokens.get_instance().app_info)

        assert AccountLinkingRecipe.__instance is not None
        return AccountLinkingRecipe.__instance

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        AccountLinkingRecipe.__instance = None

    async def get_primary_user_that_can_be_linked_to_recipe_user_id(
        self,
        tenant_id: str,
        user: User,
        user_context: Dict[str, Any],
    ) -> Optional[User]:
        # First we check if this user itself is a primary user or not. If it is, we return that.
        if user.is_primary_user:
            return user

        # Then, we try and find a primary user based on the email / phone number / third party ID.
        users = await self.recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(
                email=user.login_methods[0].email,
                phone_number=user.login_methods[0].phone_number,
                third_party=user.login_methods[0].third_party,
                # We don't need to list by (webauthn) credentialId because we are looking for
                # a user to link to the current recipe user, but any search using the credentialId
                # of the current user "will identify the same user" which is the current one.
                webauthn=None,
            ),
            do_union_of_account_info=True,
            user_context=user_context,
        )

        log_debug_message(
            "getPrimaryUserThatCanBeLinkedToRecipeUserId found %d matching users"
            % len(users)
        )
        primary_users = [u for u in users if u.is_primary_user]
        log_debug_message(
            "getPrimaryUserThatCanBeLinkedToRecipeUserId found %d matching primary users"
            % len(primary_users)
        )

        if len(primary_users) > 1:
            # This means that the new user has account info such that it's
            # spread across multiple primary user IDs. In this case, even
            # if we return one of them, it won't be able to be linked anyway
            # cause if we did, it would mean 2 primary users would have the
            # same account info. So we return None

            # This being said, with the current set of auth recipes, it should
            # never come here - cause:
            # ----> If the recipeuserid is a passwordless user, then it can have either a phone
            # email or both. If it has just one of them, then anyway 2 primary users can't
            # exist with the same phone number / email. If it has both, then the only way
            # that it can have multiple primary users returned is if there is another passwordless
            # primary user with the same phone number - which is not possible, cause phone
            # numbers are unique across passwordless users.
            #
            # ----> If the input is a third party user, then it has third party info and an email. Now there can be able to primary user with the same email, but
            # there can't be another thirdparty user with the same third party info (since that is unique).
            # Nor can there an email password primary user with the same email along with another
            # thirdparty primary user with the same email (since emails can't be the same across primary users).
            #
            # ----> If the input is an email password user, then it has an email. There can't be multiple primary users with the same email anyway.
            raise Exception(
                "You found a bug. Please report it on github.com/supertokens/supertokens-node"
            )

        return primary_users[0] if len(primary_users) > 0 else None

    async def get_oldest_user_that_can_be_linked_to_recipe_user(
        self,
        tenant_id: str,
        user: User,
        user_context: Dict[str, Any],
    ) -> Optional[User]:
        # First we check if this user itself is a primary user or not. If it is, we return that since it cannot be linked to anything else
        if user.is_primary_user:
            return user

        # Then, we try and find matching users based on the email / phone number / third party ID.
        users = await self.recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(
                email=user.login_methods[0].email,
                phone_number=user.login_methods[0].phone_number,
                third_party=user.login_methods[0].third_party,
                # We don't need to list by (webauthn) credentialId because we are looking for
                # a user to link to the current recipe user, but any search using the credentialId
                # of the current user "will identify the same user" which is the current one.
                webauthn=None,
            ),
            do_union_of_account_info=True,
            user_context=user_context,
        )

        log_debug_message(
            f"getOldestUserThatCanBeLinkedToRecipeUser found {len(users)} matching users"
        )

        # Finally select the oldest one
        oldest_user = min(users, key=lambda u: u.time_joined) if users else None
        return oldest_user

    async def is_sign_in_allowed(
        self,
        user: User,
        account_info: Union[AccountInfoWithRecipeId, LoginMethod],
        tenant_id: str,
        session: Optional[SessionContainer],
        sign_in_verifies_login_method: bool,
        user_context: Dict[str, Any],
    ) -> bool:
        ProcessState.get_instance().add_state(PROCESS_STATE.IS_SIGN_IN_ALLOWED_CALLED)
        if (
            user.is_primary_user
            or user.login_methods[0].verified
            or sign_in_verifies_login_method
        ):
            return True

        return await self.is_sign_in_up_allowed_helper(
            account_info=account_info,
            is_verified=user.login_methods[0].verified,
            session=session,
            tenant_id=tenant_id,
            is_sign_in=True,
            user=user,
            user_context=user_context,
        )

    async def is_sign_up_allowed(
        self,
        new_user: AccountInfoWithRecipeId,
        is_verified: bool,
        session: Optional[SessionContainer],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> bool:
        ProcessState.get_instance().add_state(PROCESS_STATE.IS_SIGN_UP_ALLOWED_CALLED)
        if new_user.email is not None and new_user.phone_number is not None:
            # We do this check cause below when we call list_users_by_account_info,
            # we only pass in one of email or phone number
            raise Exception("Please pass one of email or phone number, not both")

        return await self.is_sign_in_up_allowed_helper(
            account_info=new_user,
            is_verified=is_verified,
            session=session,
            tenant_id=tenant_id,
            user_context=user_context,
            user=None,
            is_sign_in=False,
        )

    async def is_sign_in_up_allowed_helper(
        self,
        account_info: Union[AccountInfoWithRecipeId, LoginMethod],
        is_verified: bool,
        session: Optional[SessionContainer],
        tenant_id: str,
        is_sign_in: bool,
        user: Optional[User],
        user_context: Dict[str, Any],
    ) -> bool:
        ProcessState.get_instance().add_state(
            PROCESS_STATE.IS_SIGN_IN_UP_ALLOWED_HELPER_CALLED
        )

        users = await self.recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(
                email=account_info.email,
                phone_number=account_info.phone_number,
                third_party=account_info.third_party,
                # We don't need to list by (webauthn) credentialId because we are looking for
                # a user to link to the current recipe user, but any search using the credentialId
                # of the current user "will identify the same user" which is the current one.
                webauthn=None,
            ),
            do_union_of_account_info=True,
            user_context=user_context,
        )

        if not users:
            log_debug_message(
                "isSignInUpAllowedHelper returning true because no user with given account info"
            )
            return True

        if is_sign_in and user is None:
            raise Exception(
                "This should never happen: isSignInUpAllowedHelper called with isSignIn: true, user: None"
            )

        if (
            len(users) == 1
            and is_sign_in
            and user is not None
            and users[0].id == user.id
        ):
            log_debug_message(
                "isSignInUpAllowedHelper returning true because this is sign in and there is only a single user with the given account info"
            )
            return True

        primary_users = [u for u in users if u.is_primary_user]

        if not primary_users:
            log_debug_message("isSignInUpAllowedHelper no primary user exists")
            should_do_account_linking = (
                await self.config.should_do_automatic_account_linking(
                    AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                        account_info
                    ),
                    None,
                    session,
                    tenant_id,
                    user_context,
                )
            )

            if isinstance(should_do_account_linking, ShouldNotAutomaticallyLink):
                log_debug_message(
                    "isSignInUpAllowedHelper returning true because account linking is disabled"
                )
                return True

            if not should_do_account_linking.should_require_verification:
                log_debug_message(
                    "isSignInUpAllowedHelper returning true because dev does not require email verification"
                )
                return True

            should_allow = True
            for curr_user in users:
                if session is not None and curr_user.id == session.get_user_id(
                    user_context
                ):
                    # We do not consider the current session user to be conflicting
                    # This can be useful in cases where the current sign in will mark the session user as verified
                    continue

                this_iteration_is_verified = False
                if account_info.email is not None:
                    if (
                        curr_user.login_methods[0].has_same_email_as(account_info.email)
                        and curr_user.login_methods[0].verified
                    ):
                        log_debug_message(
                            "isSignInUpAllowedHelper found same email for another user and verified"
                        )
                        this_iteration_is_verified = True

                if account_info.phone_number is not None:
                    if (
                        curr_user.login_methods[0].has_same_phone_number_as(
                            account_info.phone_number
                        )
                        and curr_user.login_methods[0].verified
                    ):
                        log_debug_message(
                            "isSignInUpAllowedHelper found same phone number for another user and verified"
                        )
                        this_iteration_is_verified = True

                if not this_iteration_is_verified:
                    # even if one of the users is not verified, we do not allow sign up (see why above).
                    # Sure, this allows attackers to create email password accounts with an email
                    # to block actual users from signing up, but that's ok, since those
                    # users will just see an email already exists error and then will try another
                    # login method. They can also still just go through the password reset flow
                    # and then gain access to their email password account (which can then be verified).
                    log_debug_message(
                        "isSignInUpAllowedHelper returning false cause one of the other recipe level users is not verified"
                    )
                    should_allow = False
                    break

            ProcessState.get_instance().add_state(
                PROCESS_STATE.IS_SIGN_IN_UP_ALLOWED_NO_PRIMARY_USER_EXISTS
            )
            log_debug_message(f"isSignInUpAllowedHelper returning {should_allow}")
            return should_allow
        else:
            if len(primary_users) > 1:
                raise Exception(
                    "You have found a bug. Please report to https://github.com/supertokens/supertokens-node/issues"
                )

            primary_user = primary_users[0]
            log_debug_message("isSignInUpAllowedHelper primary user found")

            should_do_account_linking = (
                await self.config.should_do_automatic_account_linking(
                    AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                        account_info
                    ),
                    primary_user,
                    session,
                    tenant_id,
                    user_context,
                )
            )

            if isinstance(should_do_account_linking, ShouldNotAutomaticallyLink):
                log_debug_message(
                    "isSignInUpAllowedHelper returning true because account linking is disabled"
                )
                return True

            if not should_do_account_linking.should_require_verification:
                log_debug_message(
                    "isSignInUpAllowedHelper returning true because dev does not require email verification"
                )
                return True

            if not is_verified:
                log_debug_message(
                    "isSignInUpAllowedHelper returning false because new user's email is not verified, and primary user with the same email was found."
                )
                return False

            if session is not None and primary_user.id == session.get_user_id(
                user_context
            ):
                return True

            for login_method in primary_user.login_methods:
                if login_method.email is not None:
                    if (
                        login_method.has_same_email_as(account_info.email)
                        and login_method.verified
                    ):
                        log_debug_message(
                            "isSignInUpAllowedHelper returning true cause found same email for primary user and verified"
                        )
                        return True

                if login_method.phone_number is not None:
                    if (
                        login_method.has_same_phone_number_as(account_info.phone_number)
                        and login_method.verified
                    ):
                        log_debug_message(
                            "isSignInUpAllowedHelper returning true cause found same phone number for primary user and verified"
                        )
                        return True

            log_debug_message(
                "isSignInUpAllowedHelper returning false cause primary user does not have the same email or phone number that is verified"
            )
            return False

    async def is_email_change_allowed(
        self,
        user: User,
        new_email: str,
        is_verified: bool,
        session: Optional[SessionContainer],
        user_context: Dict[str, Any],
    ) -> EmailChangeAllowedResult:
        """
        The purpose of this function is to check if a recipe user ID's email
        can be changed or not. There are two conditions for when it can't be changed:
        - If the recipe user is a primary user, then we need to check that the new email
        doesn't belong to any other primary user. If it does, we disallow the change
        since multiple primary user's can't have the same account info.

        - If the recipe user is NOT a primary user, and if is_verified is false, then
        we check if there exists a primary user with the same email, and if it does
        we disallow the email change cause if this email is changed, and an email
        verification email is sent, then the primary user may end up clicking
        on the link by mistake, causing account linking to happen which can result
        in account take over if this recipe user is malicious.
        """

        for tenant_id in user.tenant_ids:
            existing_users_with_new_email = (
                await self.recipe_implementation.list_users_by_account_info(
                    tenant_id=tenant_id,
                    account_info=AccountInfoInput(email=new_email),
                    do_union_of_account_info=False,
                    user_context=user_context,
                )
            )

            other_users_with_new_email = [
                u for u in existing_users_with_new_email if u.id != user.id
            ]
            other_primary_user_for_new_email = [
                u for u in other_users_with_new_email if u.is_primary_user
            ]

            if len(other_primary_user_for_new_email) > 1:
                raise Exception(
                    "You found a bug. Please report it on github.com/supertokens/supertokens-core"
                )

            if user.is_primary_user:
                if other_primary_user_for_new_email:
                    log_debug_message(
                        f"isEmailChangeAllowed: returning false cause email change will lead to two primary users having same email on {tenant_id}"
                    )
                    return EmailChangeAllowedResult(
                        allowed=False, reason="PRIMARY_USER_CONFLICT"
                    )

                if is_verified:
                    log_debug_message(
                        f"isEmailChangeAllowed: can change on {tenant_id} cause input user is primary, new email is verified and doesn't belong to any other primary user"
                    )
                    continue

                if any(
                    lm.has_same_email_as(new_email) and lm.verified
                    for lm in user.login_methods
                ):
                    log_debug_message(
                        f"isEmailChangeAllowed: can change on {tenant_id} cause input user is primary, new email is verified in another login method and doesn't belong to any other primary user"
                    )
                    continue

                if not other_users_with_new_email:
                    log_debug_message(
                        f"isEmailChangeAllowed: can change on {tenant_id} cause input user is primary and the new email doesn't belong to any other user (primary or non-primary)"
                    )
                    continue

                should_do_account_linking = await self.config.should_do_automatic_account_linking(
                    AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                        other_users_with_new_email[0].login_methods[0]
                    ),
                    user,
                    session,
                    tenant_id,
                    user_context,
                )

                if isinstance(should_do_account_linking, ShouldNotAutomaticallyLink):
                    log_debug_message(
                        f"isEmailChangeAllowed: can change on {tenant_id} cause linking is disabled"
                    )
                    continue

                if not should_do_account_linking.should_require_verification:
                    log_debug_message(
                        f"isEmailChangeAllowed: can change on {tenant_id} cause linking doesn't require email verification"
                    )
                    continue

                log_debug_message(
                    f"isEmailChangeAllowed: returning false because the user hasn't verified the new email address and there exists another user with it on {tenant_id} and linking requires verification"
                )
                return EmailChangeAllowedResult(
                    allowed=False, reason="ACCOUNT_TAKEOVER_RISK"
                )
            else:
                if is_verified:
                    log_debug_message(
                        f"isEmailChangeAllowed: can change on {tenant_id} cause input user is not a primary and new email is verified"
                    )
                    continue

                if user.login_methods[0].has_same_email_as(new_email):
                    log_debug_message(
                        f"isEmailChangeAllowed: can change on {tenant_id} cause input user is not a primary and new email is same as the older one"
                    )
                    continue

                if other_primary_user_for_new_email:
                    should_do_account_linking = (
                        await self.config.should_do_automatic_account_linking(
                            AccountInfoWithRecipeIdAndUserId(
                                recipe_id=user.login_methods[0].recipe_id,
                                email=user.login_methods[0].email,
                                recipe_user_id=user.login_methods[0].recipe_user_id,
                                phone_number=user.login_methods[0].phone_number,
                                third_party=user.login_methods[0].third_party,
                            ),
                            other_primary_user_for_new_email[0],
                            session,
                            tenant_id,
                            user_context,
                        )
                    )

                    if isinstance(
                        should_do_account_linking, ShouldNotAutomaticallyLink
                    ):
                        log_debug_message(
                            f"isEmailChangeAllowed: can change on {tenant_id} cause input user is not a primary there exists a primary user exists with the new email, but the dev does not have account linking enabled."
                        )
                        continue

                    if not should_do_account_linking.should_require_verification:
                        log_debug_message(
                            f"isEmailChangeAllowed: can change on {tenant_id} cause input user is not a primary there exists a primary user exists with the new email, but the dev does not require email verification."
                        )
                        continue

                    log_debug_message(
                        "isEmailChangeAllowed: returning false cause input user is not a primary there exists a primary user exists with the new email."
                    )
                    return EmailChangeAllowedResult(
                        allowed=False, reason="ACCOUNT_TAKEOVER_RISK"
                    )

                log_debug_message(
                    f"isEmailChangeAllowed: can change on {tenant_id} cause input user is not a primary no primary user exists with the new email"
                )
                continue

        log_debug_message(
            "isEmailChangeAllowed: returning true cause email change can happen on all tenants the user is part of"
        )
        return EmailChangeAllowedResult(allowed=True, reason="OK")

    async def verify_email_for_recipe_user_if_linked_accounts_are_verified(
        self,
        user: User,
        recipe_user_id: RecipeUserId,
        user_context: Dict[str, Any],
    ) -> None:
        if self.email_verification_recipe is None:
            return

        if user.is_primary_user:
            recipe_user_email: Optional[str] = None
            is_already_verified = False
            for lm in user.login_methods:
                if lm.recipe_user_id.get_as_string() == recipe_user_id.get_as_string():
                    recipe_user_email = lm.email
                    is_already_verified = lm.verified
                    break

            if recipe_user_email is not None:
                if is_already_verified:
                    return
                should_verify_email = False
                for lm in user.login_methods:
                    if lm.has_same_email_as(recipe_user_email) and lm.verified:
                        should_verify_email = True
                        break

                if should_verify_email:
                    ev_recipe = self.email_verification_recipe.get_instance_or_throw()
                    resp = await ev_recipe.recipe_implementation.create_email_verification_token(
                        tenant_id=user.tenant_ids[0],
                        recipe_user_id=recipe_user_id,
                        email=recipe_user_email,
                        user_context=user_context,
                    )
                    if resp.status == "OK":
                        # we purposely pass in false below cause we don't want account
                        # linking to happen
                        await ev_recipe.recipe_implementation.verify_email_using_token(
                            tenant_id=user.tenant_ids[0],
                            token=resp.token,
                            attempt_account_linking=False,
                            user_context=user_context,
                        )

    async def should_become_primary_user(
        self,
        user: User,
        tenant_id: str,
        session: Optional[SessionContainer],
        user_context: Dict[str, Any],
    ) -> bool:
        should_do_account_linking = (
            await self.config.should_do_automatic_account_linking(
                AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                    user.login_methods[0]
                ),
                None,
                session,
                tenant_id,
                user_context,
            )
        )

        if isinstance(should_do_account_linking, ShouldNotAutomaticallyLink):
            log_debug_message(
                "should_become_primary_user returning false because shouldAutomaticallyLink is false"
            )
            return False

        if (
            should_do_account_linking.should_require_verification
            and not user.login_methods[0].verified
        ):
            log_debug_message(
                "should_become_primary_user returning false because shouldRequireVerification is true but the login method is not verified"
            )
            return False

        log_debug_message("should_become_primary_user returning true")
        return True

    async def try_linking_by_account_info_or_create_primary_user(
        self,
        input_user: User,
        session: Optional[SessionContainer],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> TryLinkingByAccountInfoOrCreatePrimaryUserResult:
        tries = 0
        while tries < 100:
            tries += 1
            primary_user_that_can_be_linked_to_the_input_user = (
                await self.get_primary_user_that_can_be_linked_to_recipe_user_id(
                    tenant_id=tenant_id,
                    user=input_user,
                    user_context=user_context,
                )
            )
            if primary_user_that_can_be_linked_to_the_input_user is not None:
                log_debug_message(
                    "try_linking_by_account_info_or_create_primary_user: got primary user we can try linking"
                )
                # we check if the input_user and primary_user_that_can_be_linked_to_the_input_user are linked based on recipeIds because the input_user obj could be outdated
                if not any(
                    lm.recipe_user_id.get_as_string()
                    == input_user.login_methods[0].recipe_user_id.get_as_string()
                    for lm in primary_user_that_can_be_linked_to_the_input_user.login_methods
                ):
                    should_do_account_linking = await self.config.should_do_automatic_account_linking(
                        AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                            input_user.login_methods[0]
                        ),
                        primary_user_that_can_be_linked_to_the_input_user,
                        session,
                        tenant_id,
                        user_context,
                    )

                    if isinstance(
                        should_do_account_linking, ShouldNotAutomaticallyLink
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user: not linking because shouldAutomaticallyLink is false"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="NO_LINK", user=None
                        )

                    account_info_verified_in_prim_user = any(
                        (
                            input_user.login_methods[0].email is not None
                            and lm.has_same_email_as(input_user.login_methods[0].email)
                        )
                        or (
                            input_user.login_methods[0].phone_number is not None
                            and lm.has_same_phone_number_as(
                                input_user.login_methods[0].phone_number
                            )
                            and lm.verified
                        )
                        for lm in primary_user_that_can_be_linked_to_the_input_user.login_methods
                    )
                    if should_do_account_linking.should_require_verification and (
                        not input_user.login_methods[0].verified
                        or not account_info_verified_in_prim_user
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user: not linking because shouldRequireVerification is true but the login method is not verified in the new or the primary user"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="NO_LINK", user=None
                        )

                    log_debug_message(
                        "try_linking_by_account_info_or_create_primary_user linking"
                    )
                    link_accounts_result = await self.recipe_implementation.link_accounts(
                        recipe_user_id=input_user.login_methods[0].recipe_user_id,
                        primary_user_id=primary_user_that_can_be_linked_to_the_input_user.id,
                        user_context=user_context,
                    )

                    if link_accounts_result.status == "OK":
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user successfully linked"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="OK", user=link_accounts_result.user
                        )
                    elif (
                        link_accounts_result.status
                        == "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user already linked to another user"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="OK", user=link_accounts_result.user
                        )
                    elif (
                        link_accounts_result.status
                        == "INPUT_USER_IS_NOT_A_PRIMARY_USER"
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user linking failed because of a race condition"
                        )
                        continue
                    else:
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user linking failed because of a race condition"
                        )
                        continue
                return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                    status="OK", user=input_user
                )

            oldest_user_that_can_be_linked_to_the_input_user = (
                await self.get_oldest_user_that_can_be_linked_to_recipe_user(
                    tenant_id=tenant_id,
                    user=input_user,
                    user_context=user_context,
                )
            )
            if (
                oldest_user_that_can_be_linked_to_the_input_user is not None
                and oldest_user_that_can_be_linked_to_the_input_user.id != input_user.id
            ):
                log_debug_message(
                    "try_linking_by_account_info_or_create_primary_user: got an older user we can try linking"
                )
                should_make_older_user_primary = await self.should_become_primary_user(
                    oldest_user_that_can_be_linked_to_the_input_user,
                    tenant_id,
                    session,
                    user_context,
                )
                if should_make_older_user_primary:
                    create_primary_user_result = await self.recipe_implementation.create_primary_user(
                        recipe_user_id=oldest_user_that_can_be_linked_to_the_input_user.login_methods[
                            0
                        ].recipe_user_id,
                        user_context=user_context,
                    )
                    if (
                        create_primary_user_result.status
                        == "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
                        or create_primary_user_result.status
                        == "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
                    ):
                        log_debug_message(
                            f"try_linking_by_account_info_or_create_primary_user: retrying because createPrimaryUser returned {create_primary_user_result.status}"
                        )
                        continue
                    should_do_account_linking = await self.config.should_do_automatic_account_linking(
                        AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                            input_user.login_methods[0]
                        ),
                        create_primary_user_result.user,
                        session,
                        tenant_id,
                        user_context,
                    )

                    if isinstance(
                        should_do_account_linking, ShouldNotAutomaticallyLink
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user: not linking because shouldAutomaticallyLink is false"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="NO_LINK", user=None
                        )

                    if (
                        should_do_account_linking.should_require_verification
                        and not input_user.login_methods[0].verified
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user: not linking because shouldRequireVerification is true but the login method is not verified"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="NO_LINK", user=None
                        )

                    log_debug_message(
                        "try_linking_by_account_info_or_create_primary_user linking"
                    )
                    link_accounts_result = (
                        await self.recipe_implementation.link_accounts(
                            recipe_user_id=input_user.login_methods[0].recipe_user_id,
                            primary_user_id=create_primary_user_result.user.id,
                            user_context=user_context,
                        )
                    )

                    if link_accounts_result.status == "OK":
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user successfully linked"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="OK", user=link_accounts_result.user
                        )
                    elif (
                        link_accounts_result.status
                        == "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user already linked to another user"
                        )
                        return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                            status="OK", user=link_accounts_result.user
                        )
                    elif (
                        link_accounts_result.status
                        == "INPUT_USER_IS_NOT_A_PRIMARY_USER"
                    ):
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user linking failed because of a race condition"
                        )
                        continue
                    else:
                        log_debug_message(
                            "try_linking_by_account_info_or_create_primary_user linking failed because of a race condition"
                        )
                        continue

            log_debug_message(
                "try_linking_by_account_info_or_create_primary_user: trying to make the current user primary"
            )

            if await self.should_become_primary_user(
                input_user, tenant_id, session, user_context
            ):
                create_primary_user_result = (
                    await self.recipe_implementation.create_primary_user(
                        recipe_user_id=input_user.login_methods[0].recipe_user_id,
                        user_context=user_context,
                    )
                )

                if (
                    create_primary_user_result.status
                    == "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
                    or create_primary_user_result.status
                    == "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
                ):
                    continue
                return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                    status="OK",
                    user=create_primary_user_result.user,
                )
            else:
                return TryLinkingByAccountInfoOrCreatePrimaryUserResult(
                    status="OK", user=input_user
                )

        raise Exception(
            "This should never happen: ran out of retries for try_linking_by_account_info_or_create_primary_user"
        )
