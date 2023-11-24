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
from ...types import MaybeAwaitable
from ...utils import get_timestamp_ms
from ..session import SessionRecipe
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
        get_email_for_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
        override: Union[OverrideConfig, None] = None,
    ) -> None:
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            app_info,
            mode,
            email_delivery,
            get_email_for_user_id,
            override,
        )

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config
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

        self.get_email_for_user_id_funcs_from_other_recipes: List[
            TypeGetEmailForUserIdFunction
        ] = []

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
        get_email_for_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
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
                    get_email_for_user_id,
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

                PostSTInitCallbacks.add_post_init_callback(callback)

                return EmailVerificationRecipe.__instance
            raise_general_exception(
                "Emailverification recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> EmailVerificationRecipe:
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

    async def get_email_for_user_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[GetEmailForUserIdOkResult, EmailDoesNotExistError, UnknownUserIdError]:
        if self.config.get_email_for_user_id is not None:
            res = await self.config.get_email_for_user_id(user_id, user_context)
            if not isinstance(res, UnknownUserIdError):
                return res

        for f in self.get_email_for_user_id_funcs_from_other_recipes:
            res = await f(user_id, user_context)
            if not isinstance(res, UnknownUserIdError):
                return res

        return UnknownUserIdError()

    def add_get_email_for_user_id_func(self, f: TypeGetEmailForUserIdFunction):
        self.get_email_for_user_id_funcs_from_other_recipes.append(f)


class EmailVerificationClaimValidators(BooleanClaimValidators):
    def __init__(self, claim: EmailVerificationClaimClass, default_max_age_in_sec: int):
        super().__init__(claim, default_max_age_in_sec)
        # required to override the type as "int":
        self.default_max_age_in_sec = default_max_age_in_sec

    def is_verified(
        self,
        refetch_time_on_false_in_seconds: int = 10,
        max_age_in_seconds: Optional[int] = None,
        id_: Optional[str] = None,
    ) -> SessionClaimValidator:
        max_age_in_seconds = max_age_in_seconds or self.default_max_age_in_sec

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
        default_max_age_in_sec = 300

        async def fetch_value(
            user_id: str, _tenant_id: str, user_context: Dict[str, Any]
        ) -> bool:
            recipe = EmailVerificationRecipe.get_instance()
            email_info = await recipe.get_email_for_user_id(user_id, user_context)

            if isinstance(email_info, GetEmailForUserIdOkResult):
                return await recipe.recipe_implementation.is_email_verified(
                    user_id, email_info.email, user_context
                )
            if isinstance(email_info, EmailDoesNotExistError):
                # we consider people without email addresses as validated
                return True
            raise Exception("UNKNOWN_USER_ID")

        super().__init__("st-ev", fetch_value, default_max_age_in_sec)

        self.validators = EmailVerificationClaimValidators(
            claim=self, default_max_age_in_sec=default_max_age_in_sec
        )


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
            token, tenant_id, user_context
        )
        if isinstance(response, VerifyEmailUsingTokenOkResult):
            if session is not None:
                try:
                    await session.fetch_and_set_claim(
                        EmailVerificationClaim, user_context
                    )
                except Exception as e:
                    # This should never happen since we have just set the status above
                    if str(e) == "UNKNOWN_USER_ID":
                        log_debug_message(
                            "verifyEmailPOST: Returning UNAUTHORISED because the user id provided is unknown"
                        )
                        raise_unauthorised_exception("Unknown User ID provided")
                    else:
                        raise e

            return EmailVerifyPostOkResult(response.user)
        return EmailVerifyPostInvalidTokenError()

    async def is_email_verified_get(
        self,
        session: SessionContainer,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> IsEmailVerifiedGetOkResult:
        if session is None:
            raise Exception("Session is undefined. Should not come here.")
        try:
            await session.fetch_and_set_claim(EmailVerificationClaim, user_context)
        except Exception as e:
            if str(e) == "UNKNOWN_USER_ID":
                log_debug_message(
                    "isEmailVerifiedGET: Returning UNAUTHORISED because the user id provided is unknown"
                )
                raise_unauthorised_exception("Unknown User ID provided")
            else:
                raise e

        is_verified = await session.get_claim_value(
            EmailVerificationClaim, user_context
        )

        if is_verified is None:
            raise Exception(
                "Should never come here: EmailVerificationClaim failed to set value"
            )

        return IsEmailVerifiedGetOkResult(is_verified)

    async def generate_email_verify_token_post(
        self,
        session: SessionContainer,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        GenerateEmailVerifyTokenPostOkResult,
        GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
    ]:
        user_id = session.get_user_id(user_context)
        email_info = await EmailVerificationRecipe.get_instance().get_email_for_user_id(
            user_id, user_context
        )
        tenant_id = session.get_tenant_id()

        if isinstance(email_info, EmailDoesNotExistError):
            log_debug_message(
                "Email verification email not sent to user %s because it doesn't have an email address.",
                user_id,
            )
            return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError()
        if isinstance(email_info, GetEmailForUserIdOkResult):
            response = (
                await api_options.recipe_implementation.create_email_verification_token(
                    user_id,
                    email_info.email,
                    tenant_id,
                    user_context,
                )
            )

            if isinstance(
                response, CreateEmailVerificationTokenEmailAlreadyVerifiedError
            ):
                if await session.get_claim_value(EmailVerificationClaim) is not True:
                    # this can happen if the email was "verified" in another browser
                    # and this session is still outdated - and the user has not
                    # called the get email verification API yet.
                    await session.fetch_and_set_claim(
                        EmailVerificationClaim, user_context
                    )
                log_debug_message(
                    "Email verification email not sent to %s because it is already verified.",
                    email_info.email,
                )
                return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError()

            if await session.get_claim_value(EmailVerificationClaim) is not False:
                # this can happen if the email was "unverified" in another browser
                # and this session is still outdated - and the user has not
                # called the get email verification API yet.
                await session.fetch_and_set_claim(EmailVerificationClaim, user_context)

            email_verify_link = get_email_verify_link(
                api_options.app_info,
                response.token,
                api_options.recipe_id,
                tenant_id,
                api_options.request,
                user_context,
            )

            log_debug_message("Sending email verification email to %s", email_info)
            email_verification_email_delivery_input = VerificationEmailTemplateVars(
                user=VerificationEmailTemplateVarsUser(user_id, email_info.email),
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
        max_age_in_seconds: int,
    ):
        super().__init__(id_)
        self.claim: EmailVerificationClaimClass = claim
        self.ev_claim_validators = ev_claim_validators
        self.refetch_time_on_false_in_ms = refetch_time_on_false_in_seconds * 1000
        self.max_age_in_sec = max_age_in_seconds
        self.max_age_in_ms = max_age_in_seconds * 1000

    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        return await self.ev_claim_validators.has_value(
            True, self.max_age_in_sec
        ).validate(payload, user_context)

    def should_refetch(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> MaybeAwaitable[bool]:
        value = self.claim.get_value_from_payload(payload, user_context)
        if value is None:
            return True

        last_refetch_time = self.claim.get_last_refetch_time(payload, user_context)
        assert last_refetch_time is not None

        return (last_refetch_time < get_timestamp_ms() - self.max_age_in_ms) or (
            value is False
            and (
                last_refetch_time
                < (get_timestamp_ms() - self.refetch_time_on_false_in_ms)
            )
        )
