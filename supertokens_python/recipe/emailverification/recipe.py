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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.recipe.emailverification.exceptions import (
    EmailVerificationInvalidTokenError,
)
from supertokens_python.recipe.emailverification.types import (
    EmailTemplateVars,
    EmailVerificationIngredients,
    VerificationEmailTemplateVars,
    VerificationEmailTemplateVarsUser,
)
from supertokens_python.recipe_module import APIHandled, RecipeModule

from ...ingredients.emaildelivery.types import EmailDeliveryConfig
from ...logger import log_debug_message
from ...post_init_callbacks import PostSTInitCallbacks
from ...utils import get_timestamp_ms
from ..session import SessionRecipe
from ..session.asyncio import create_new_session, revoke_all_sessions_for_user
from ..session.claim_base_classes.boolean_claim import (
    BooleanClaim,
    BooleanClaimValidators,
)
from ..session.exceptions import raise_unauthorised_exception
from ..session.interfaces import (
    ClaimValidationResult,
    JSONObject,
    SessionClaimValidator,
    SessionContainer,
)
from .interfaces import (
    APIInterface,
    APIOptions,
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    EmailDoesNotExistError,
    EmailVerifyPostInvalidTokenError,
    EmailVerifyPostOkResult,
    GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
    GenerateEmailVerifyTokenPostOkResult,
    GetEmailForUserIdOkResult,
    IsEmailVerifiedGetOkResult,
    TypeGetEmailForUserIdFunction,
    UnknownUserIdError,
    VerifyEmailUsingTokenOkResult,
)
from .recipe_implementation import RecipeImplementation

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.types import RecipeUserId

    from ...types import MaybeAwaitable, User

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.emailverification.utils import get_email_verify_link

from .api import handle_email_verify_api, handle_generate_email_verify_token_api
from .constants import USER_EMAIL_VERIFY, USER_EMAIL_VERIFY_TOKEN
from .exceptions import SuperTokensEmailVerificationError
from .utils import MODE_TYPE, OverrideConfig, validate_and_normalise_user_input


class EmailVerificationRecipe(RecipeModule):
    recipe_id = "emailverification"
    __instance = None
    email_delivery: EmailDeliveryIngredient[VerificationEmailTemplateVars]

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        ingredients: EmailVerificationIngredients,
        mode: MODE_TYPE,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
        get_email_for_recipe_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
        override: Union[OverrideConfig, None] = None,
    ) -> None:
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            app_info,
            mode,
            email_delivery,
            get_email_for_recipe_user_id,
            override,
        )

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id),
            self.get_email_for_recipe_user_id,
        )
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        api_implementation = APIImplementation()
        self.api_implementation = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

        email_delivery_ingredient = ingredients.email_delivery
        if email_delivery_ingredient is None:
            self.email_delivery = EmailDeliveryIngredient(
                self.config.get_email_delivery_config()
            )
        else:
            self.email_delivery = email_delivery_ingredient

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and isinstance(
            err, SuperTokensEmailVerificationError
        )

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                NormalisedURLPath(USER_EMAIL_VERIFY_TOKEN),
                "post",
                USER_EMAIL_VERIFY_TOKEN,
                self.api_implementation.disable_generate_email_verify_token_post,
            ),
            APIHandled(
                NormalisedURLPath(USER_EMAIL_VERIFY),
                "post",
                USER_EMAIL_VERIFY,
                self.api_implementation.disable_email_verify_post,
            ),
            APIHandled(
                NormalisedURLPath(USER_EMAIL_VERIFY),
                "get",
                USER_EMAIL_VERIFY,
                self.api_implementation.disable_is_email_verified_get,
            ),
        ]

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Union[BaseResponse, None]:
        api_options = APIOptions(
            request,
            response,
            self.recipe_id,
            self.config,
            self.recipe_implementation,
            self.get_app_info(),
            self.email_delivery,
        )
        if request_id == USER_EMAIL_VERIFY_TOKEN:
            return await handle_generate_email_verify_token_api(
                self.api_implementation, api_options, user_context
            )
        return await handle_email_verify_api(
            self.api_implementation, tenant_id, api_options, user_context
        )

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        if isinstance(err, EmailVerificationInvalidTokenError):
            response.set_json_content(
                {"status": "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR"}
            )
            return response
        response.set_json_content({"status": "EMAIL_ALREADY_VERIFIED_ERROR"})
        return response

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(
        mode: MODE_TYPE,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
        get_email_for_recipe_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
        override: Union[OverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo) -> EmailVerificationRecipe:
            if EmailVerificationRecipe.__instance is None:
                ingredients = EmailVerificationIngredients(email_delivery=None)
                EmailVerificationRecipe.__instance = EmailVerificationRecipe(
                    EmailVerificationRecipe.recipe_id,
                    app_info,
                    ingredients,
                    mode,
                    email_delivery,
                    get_email_for_recipe_user_id,
                    override,
                )

                def callback():
                    SessionRecipe.get_instance().add_claim_from_other_recipe(
                        EmailVerificationClaim
                    )
                    if mode == "REQUIRED":
                        SessionRecipe.get_instance().add_claim_validator_from_other_recipe(
                            EmailVerificationClaim.validators.is_verified()
                        )

                    from supertokens_python.recipe.accountlinking.recipe import (
                        AccountLinkingRecipe,
                    )

                    assert EmailVerificationRecipe.__instance is not None
                    AccountLinkingRecipe.get_instance().register_email_verification_recipe(
                        EmailVerificationRecipe.__instance
                    )

                PostSTInitCallbacks.add_post_init_callback(callback)

                return EmailVerificationRecipe.__instance
            raise_general_exception(
                "Emailverification recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance_or_throw() -> EmailVerificationRecipe:
        if EmailVerificationRecipe.__instance is not None:
            return EmailVerificationRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def get_instance_optional() -> Optional[EmailVerificationRecipe]:
        return EmailVerificationRecipe.__instance

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        EmailVerificationRecipe.__instance = None

    async def get_email_for_recipe_user_id(
        self,
        user: Optional[User],
        recipe_user_id: RecipeUserId,
        user_context: Dict[str, Any],
    ) -> Union[GetEmailForUserIdOkResult, EmailDoesNotExistError, UnknownUserIdError]:
        if self.config.get_email_for_recipe_user_id is not None:
            user_res = await self.config.get_email_for_recipe_user_id(
                recipe_user_id, user_context
            )
            if not isinstance(user_res, UnknownUserIdError):
                return user_res

        if user is None:
            from supertokens_python.recipe.accountlinking.recipe import (
                AccountLinkingRecipe,
            )

            user = await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
                recipe_user_id.get_as_string(), user_context
            )

            if user is None:
                return UnknownUserIdError()

        for login_method in user.login_methods:
            if (
                login_method.recipe_user_id.get_as_string()
                == recipe_user_id.get_as_string()
            ):
                if login_method.email is not None:
                    return GetEmailForUserIdOkResult(email=login_method.email)
                else:
                    return EmailDoesNotExistError()

        return UnknownUserIdError()

    async def get_primary_user_id_for_recipe_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> str:
        # We extract this into its own function like this cause we want to make sure that
        # this recipe does not get the email of the user ID from the getUser function.
        # In fact, there is a test "email verification recipe uses getUser function only in getEmailForRecipeUserId"
        # which makes sure that this function is only called in 3 places in this recipe:
        # - this function
        # - getEmailForRecipeUserId function (above)
        # - after verification to get the updated user in verifyEmailUsingToken
        # We want to isolate the result of calling this function as much as possible
        # so that the consumer of the getUser function does not read the email
        # from the primaryUser. Hence, this function only returns the string ID
        # and nothing else from the primaryUser.
        from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe

        primary_user = (
            await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
                recipe_user_id.get_as_string(), user_context
            )
        )
        if primary_user is None:
            # This can come here if the user is using session + email verification
            # recipe with a user ID that is not known to supertokens. In this case,
            # we do not allow linking for such users.
            return recipe_user_id.get_as_string()
        return primary_user.id

    async def update_session_if_required_post_email_verification(
        self,
        req: BaseRequest,
        session: Optional[SessionContainer],
        recipe_user_id_whose_email_got_verified: RecipeUserId,
        user_context: Dict[str, Any],
    ) -> Optional[SessionContainer]:
        primary_user_id = await self.get_primary_user_id_for_recipe_user(
            recipe_user_id_whose_email_got_verified, user_context
        )

        # if a session exists in the API, then we can update the session
        # claim related to email verification
        if session is not None:
            log_debug_message(
                "updateSessionIfRequiredPostEmailVerification got session"
            )
            # Due to linking, we will have to correct the current
            # session's user ID. There are four cases here:
            # --> (Case 1) User signed up and did email verification and the new account
            # became a primary user (user ID no change)
            # --> (Case 2) User signed up and did email verification and the new account got linked
            # to another primary user (user ID change)
            # --> (Case 3) This is post login account linking, in which the account that got verified
            # got linked to the session's account (user ID of account has changed to the session's user ID)
            # -->  (Case 4) This is post login account linking, in which the account that got verified
            # got linked to ANOTHER primary account (user ID of account has changed to a different user ID != session.getUserId, but
            # we should ignore this since it will result in the user's session changing.)

            if (
                session.get_recipe_user_id(user_context).get_as_string()
                == recipe_user_id_whose_email_got_verified.get_as_string()
            ):
                log_debug_message(
                    "updateSessionIfRequiredPostEmailVerification the session belongs to the verified user"
                )
                # this means that the session's login method's account is the
                # one that just got verified and that we are NOT doing post login
                # account linking. So this is only for (Case 1) and (Case 2)

                if session.get_user_id() == primary_user_id:
                    log_debug_message(
                        "updateSessionIfRequiredPostEmailVerification the session userId matches the primary user id, so we are only refreshing the claim"
                    )
                    # if the session's primary user ID is equal to the
                    # primary user ID that the account was linked to, then
                    # this means that the new account became a primary user (Case 1)
                    # We also have the sub cases here that the account that just
                    # got verified was already linked to the session's primary user ID,
                    # but either way, we don't need to change any user ID.

                    # In this case, all we do is to update the emailverification claim
                    try:
                        # EmailVerificationClaim will be based on the recipeUserId
                        # and not the primary user ID.
                        await session.fetch_and_set_claim(
                            EmailVerificationClaim, user_context
                        )
                    except Exception as err:
                        # This should never happen, since we've just set the status above.
                        if str(err) == "UNKNOWN_USER_ID":
                            raise_unauthorised_exception("Unknown User ID provided")
                        raise err

                    return None
                else:
                    log_debug_message(
                        "updateSessionIfRequiredPostEmailVerification the session user id doesn't match the primary user id, so we are revoking all sessions and creating a new one"
                    )
                    # if the session's primary user ID is NOT equal to the
                    # primary user ID that the account that it was linked to, then
                    # this means that the new account got linked to another primary user (Case 2)

                    # In this case, we need to update the session's user ID by creating
                    # a new session

                    # Revoke all session belonging to session.getRecipeUserId()
                    # We do not really need to do this, but we do it anyway.. no harm.
                    await revoke_all_sessions_for_user(
                        recipe_user_id_whose_email_got_verified.get_as_string(),
                        False,
                        None,
                        user_context,
                    )

                    # create a new session and return that..
                    return await create_new_session(
                        req,
                        session.get_tenant_id(),
                        session.get_recipe_user_id(user_context),
                        {},
                        {},
                        user_context,
                    )
            else:
                log_debug_message(
                    "updateSessionIfRequiredPostEmailVerification the verified user doesn't match the session"
                )
                # this means that the session's login method's account was NOT the
                # one that just got verified and that we ARE doing post login
                # account linking. So this is only for (Case 3) and (Case 4)

                # In both case 3 and case 4, we do not want to change anything in the
                # current session in terms of user ID or email verification claim (since
                # both of these refer to the current logged in user and not the newly
                # linked user's account).

                return None
        else:
            log_debug_message(
                "updateSessionIfRequiredPostEmailVerification got no session"
            )
            # the session is updated when the is email verification GET API is called
            # so we don't do anything in this API.
            return None


class EmailVerificationClaimValidators(BooleanClaimValidators):
    def __init__(self, claim: EmailVerificationClaimClass):
        super().__init__(claim, None)

    def is_verified(
        self,
        refetch_time_on_false_in_seconds: int = 10,
        max_age_in_seconds: Optional[int] = None,
        id_: Optional[str] = None,
    ) -> SessionClaimValidator:
        assert isinstance(self.claim, EmailVerificationClaimClass)
        return IsVerifiedSCV(
            (id_ or self.claim.key),
            self.claim,
            self,
            refetch_time_on_false_in_seconds,
            max_age_in_seconds,
        )


class EmailVerificationClaimClass(BooleanClaim):
    def __init__(self):
        async def fetch_value(
            _: str,
            recipe_user_id: RecipeUserId,
            __: str,
            ___: Dict[str, Any],
            user_context: Dict[str, Any],
        ) -> bool:
            recipe = EmailVerificationRecipe.get_instance_or_throw()
            email_info = await recipe.get_email_for_recipe_user_id(
                None, recipe_user_id, user_context
            )

            if isinstance(email_info, GetEmailForUserIdOkResult):
                return await recipe.recipe_implementation.is_email_verified(
                    recipe_user_id, email_info.email, user_context
                )
            if isinstance(email_info, EmailDoesNotExistError):
                # we consider people without email addresses as validated
                return True
            raise Exception("UNKNOWN_USER_ID")

        super().__init__("st-ev", fetch_value, None)

        self.validators = EmailVerificationClaimValidators(claim=self)


EmailVerificationClaim = EmailVerificationClaimClass()


class APIImplementation(APIInterface):
    async def email_verify_post(
        self,
        token: str,
        session: Optional[SessionContainer],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailVerifyPostOkResult, EmailVerifyPostInvalidTokenError]:
        response = await api_options.recipe_implementation.verify_email_using_token(
            token, tenant_id, True, user_context
        )
        if isinstance(response, VerifyEmailUsingTokenOkResult):
            email_verification_recipe = EmailVerificationRecipe.get_instance_or_throw()
            new_session = await email_verification_recipe.update_session_if_required_post_email_verification(
                api_options.request, session, response.user.recipe_user_id, user_context
            )

            return EmailVerifyPostOkResult(response.user, new_session)
        return EmailVerifyPostInvalidTokenError()

    async def is_email_verified_get(
        self,
        session: SessionContainer,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> IsEmailVerifiedGetOkResult:
        recipe = EmailVerificationRecipe.get_instance_or_throw()
        email_info = await recipe.get_email_for_recipe_user_id(
            None, session.get_recipe_user_id(user_context), user_context
        )

        if isinstance(email_info, GetEmailForUserIdOkResult):
            is_verified = await api_options.recipe_implementation.is_email_verified(
                session.get_recipe_user_id(user_context), email_info.email, user_context
            )

            if is_verified:
                new_session = (
                    await recipe.update_session_if_required_post_email_verification(
                        api_options.request,
                        session,
                        session.get_recipe_user_id(user_context),
                        user_context,
                    )
                )
                return IsEmailVerifiedGetOkResult(True, new_session)
            else:
                await session.set_claim_value(
                    EmailVerificationClaim, False, user_context
                )
                return IsEmailVerifiedGetOkResult(False, None)
        elif isinstance(email_info, EmailDoesNotExistError):
            # We consider people without email addresses as validated
            return IsEmailVerifiedGetOkResult(True, None)
        else:
            # This means that the user ID is not known to supertokens. This could
            # happen if the current session's user ID is not an auth user,
            # or if it belongs to a recipe user ID that got deleted. Either way,
            # we logout the user.
            raise_unauthorised_exception("Unknown User ID provided")

    async def generate_email_verify_token_post(
        self,
        session: SessionContainer,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        GenerateEmailVerifyTokenPostOkResult,
        GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
    ]:
        tenant_id = session.get_tenant_id()

        email_info = await EmailVerificationRecipe.get_instance_or_throw().get_email_for_recipe_user_id(
            None, session.get_recipe_user_id(user_context), user_context
        )

        if isinstance(email_info, EmailDoesNotExistError):
            log_debug_message(
                "Email verification email not sent to user %s because it doesn't have an email address.",
                session.get_recipe_user_id(user_context).get_as_string(),
            )
            # This can happen if the user ID was found, but it has no email. In this
            # case, we treat it as a success case.
            new_session = await EmailVerificationRecipe.get_instance_or_throw().update_session_if_required_post_email_verification(
                api_options.request,
                session,
                session.get_recipe_user_id(user_context),
                user_context,
            )
            return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError(new_session)
        elif isinstance(email_info, GetEmailForUserIdOkResult):
            response = (
                await api_options.recipe_implementation.create_email_verification_token(
                    session.get_recipe_user_id(user_context),
                    email_info.email,
                    tenant_id,
                    user_context,
                )
            )

            if isinstance(
                response, CreateEmailVerificationTokenEmailAlreadyVerifiedError
            ):
                log_debug_message(
                    "Email verification email not sent to user %s because it is already verified.",
                    session.get_recipe_user_id(user_context).get_as_string(),
                )
                new_session = await EmailVerificationRecipe.get_instance_or_throw().update_session_if_required_post_email_verification(
                    api_options.request,
                    session,
                    session.get_recipe_user_id(user_context),
                    user_context,
                )
                return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError(
                    new_session
                )

            if (
                await session.get_claim_value(EmailVerificationClaim, user_context)
                is not False
            ):
                # This can happen if the email was unverified in another browser
                # and this session is still outdated - and the user has not
                # called the get email verification API yet.
                await session.fetch_and_set_claim(EmailVerificationClaim, user_context)

            email_verify_link = get_email_verify_link(
                api_options.app_info,
                response.token,
                tenant_id,
                api_options.request,
                user_context,
            )

            log_debug_message(
                "Sending email verification email to %s", email_info.email
            )
            email_verification_email_delivery_input = VerificationEmailTemplateVars(
                user=VerificationEmailTemplateVarsUser(
                    _id=session.get_user_id(user_context),
                    recipe_user_id=session.get_recipe_user_id(user_context),
                    email=email_info.email,
                ),
                email_verify_link=email_verify_link,
                tenant_id=tenant_id,
            )
            await api_options.email_delivery.ingredient_interface_impl.send_email(
                email_verification_email_delivery_input, user_context
            )
            return GenerateEmailVerifyTokenPostOkResult()

        log_debug_message(
            "generateEmailVerifyTokenPOST: Returning UNAUTHORISED because the user id provided is unknown"
        )
        raise_unauthorised_exception("Unknown User ID provided")


class IsVerifiedSCV(SessionClaimValidator):
    def __init__(
        self,
        id_: str,
        claim: EmailVerificationClaimClass,
        ev_claim_validators: EmailVerificationClaimValidators,
        refetch_time_on_false_in_seconds: int,
        max_age_in_seconds: Optional[int],
    ):
        super().__init__(id_)
        self.claim = claim
        self.ev_claim_validators = ev_claim_validators
        self.refetch_time_on_false_in_ms = refetch_time_on_false_in_seconds * 1000
        self.max_age_in_sec = max_age_in_seconds

    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        return await self.ev_claim_validators.has_value(
            True, self.max_age_in_sec
        ).validate(payload, user_context)

    def should_refetch(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> MaybeAwaitable[bool]:
        if self.claim is None:
            raise Exception("should never happen")

        if not isinstance(self.claim, EmailVerificationClaimClass):
            raise Exception("should never happen")

        value = self.claim.get_value_from_payload(payload, user_context)
        if value is None:
            return True

        current_time = get_timestamp_ms()
        last_refetch_time = self.claim.get_last_refetch_time(payload, user_context)
        assert last_refetch_time is not None

        if self.max_age_in_sec is not None:
            if last_refetch_time < current_time - self.max_age_in_sec * 1000:
                return True

        if value is False:
            if last_refetch_time < current_time - self.refetch_time_on_false_in_ms:
                return True

        return False
