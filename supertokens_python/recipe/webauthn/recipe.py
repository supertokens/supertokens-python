# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

import os
from typing import TYPE_CHECKING, Any, Dict, List, Optional, cast

from supertokens_python.auth_utils import is_fake_email
from supertokens_python.exceptions import raise_general_exception
from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.post_init_callbacks import PostSTInitCallbacks
from supertokens_python.querier import Querier
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multifactorauth.types import (
    FactorIds,
    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc,
    GetEmailsForFactorFromOtherRecipesFunc,
    GetEmailsForFactorOkResult,
    GetEmailsForFactorUnknownSessionRecipeUserIdResult,
    GetFactorsSetupForUserFromOtherRecipesFunc,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.webauthn.api.email_exists import email_exists_api
from supertokens_python.recipe.webauthn.api.generate_recover_account_token import (
    generate_recover_account_token_api,
)
from supertokens_python.recipe.webauthn.api.implementation import APIImplementation
from supertokens_python.recipe.webauthn.api.recover_account import recover_account_api
from supertokens_python.recipe.webauthn.api.register_credentials import (
    register_credential_api,
)
from supertokens_python.recipe.webauthn.api.register_options import register_options_api
from supertokens_python.recipe.webauthn.api.sign_in import sign_in_api
from supertokens_python.recipe.webauthn.api.sign_in_options import sign_in_options_api
from supertokens_python.recipe.webauthn.api.sign_up import sign_up_api
from supertokens_python.recipe.webauthn.constants import (
    GENERATE_RECOVER_ACCOUNT_TOKEN_API,
    RECOVER_ACCOUNT_API,
    REGISTER_CREDENTIAL_API,
    REGISTER_OPTIONS_API,
    SIGN_IN_API,
    SIGN_UP_API,
    SIGNIN_OPTIONS_API,
    SIGNUP_EMAIL_EXISTS_API,
)
from supertokens_python.recipe.webauthn.exceptions import WebauthnError
from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface
from supertokens_python.recipe.webauthn.recipe_implementation import (
    RecipeImplementation,
)
from supertokens_python.recipe.webauthn.types.config import (
    NormalisedWebauthnConfig,
    WebauthnConfig,
    WebauthnIngredients,
)
from supertokens_python.recipe.webauthn.utils import validate_and_normalise_user_input
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.supertokens import AppInfo
from supertokens_python.types.base import RecipeUserId, User, UserContext

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import (
        APIInterface,
        TypeWebauthnEmailDeliveryInput,
    )


class WebauthnRecipe(RecipeModule):
    __instance: Optional["WebauthnRecipe"] = None
    recipe_id = "webauthn"

    config: NormalisedWebauthnConfig
    recipe_implementation: RecipeInterface
    api_implementation: "APIInterface"
    email_delivery: EmailDeliveryIngredient["TypeWebauthnEmailDeliveryInput"]

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        config: Optional[WebauthnConfig],
        ingredients: WebauthnIngredients,
    ):
        super().__init__(recipe_id=recipe_id, app_info=app_info)
        self.config = validate_and_normalise_user_input(
            app_info=app_info, config=config
        )

        querier = Querier.get_instance(rid_to_core=recipe_id)
        recipe_implementation = RecipeImplementation(
            querier=querier,
            config=self.config,
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

        if ingredients.email_delivery is None:
            self.email_delivery = EmailDeliveryIngredient(
                config=self.config.get_email_delivery_config()
            )
        else:
            self.email_delivery = ingredients.email_delivery

        def callback():
            mfa_instance = MultiFactorAuthRecipe.get_instance()
            if mfa_instance is not None:

                async def get_available_secondary_factor_ids(
                    _: TenantConfig,
                ) -> List[str]:
                    return ["emailpassword"]

                mfa_instance.add_func_to_get_all_available_secondary_factor_ids_from_other_recipes(
                    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc(
                        get_available_secondary_factor_ids
                    )
                )

                async def user_setup(user: User, _: Dict[str, Any]) -> List[str]:
                    for login_method in user.login_methods:
                        # We don't check for tenantId here because if we find the user
                        # with emailpassword loginMethod from different tenant, then
                        # we assume the factor is setup for this user. And as part of factor
                        # completion, we associate that loginMethod with the session's tenantId
                        if login_method.recipe_id == self.recipe_id:
                            return ["emailpassword"]

                    return []

                mfa_instance.add_func_to_get_factors_setup_for_user_from_other_recipes(
                    GetFactorsSetupForUserFromOtherRecipesFunc(user_setup)
                )

                async def get_emails_for_factor(
                    user: User, session_recipe_user_id: RecipeUserId
                ):
                    session_login_method = None
                    for login_method in user.login_methods:
                        if (
                            login_method.recipe_user_id.get_as_string()
                            == session_recipe_user_id.get_as_string()
                        ):
                            session_login_method = login_method
                            break

                    if session_login_method is None:
                        # this can happen maybe cause this login method
                        # was unlinked from the user or deleted entirely
                        return GetEmailsForFactorUnknownSessionRecipeUserIdResult()

                    # We order the login methods based on `time_joined` (oldest first)
                    ordered_login_methods = sorted(
                        user.login_methods, key=lambda lm: lm.time_joined, reverse=True
                    )
                    # We take the ones that belong to this recipe
                    recipe_ordered_login_methods = list(
                        filter(
                            lambda lm: lm.recipe_id == self.recipe_id,
                            ordered_login_methods,
                        )
                    )

                    result: List[str] = []
                    if len(recipe_ordered_login_methods) == 0:
                        # If there are login methods belonging to this recipe, the factor is set up
                        # In this case we only list email addresses that have a password associated with them

                        # First we take the verified real emails associated with emailpassword login methods ordered by timeJoined (oldest first)
                        result.extend(
                            [
                                cast(str, lm.email)
                                for lm in recipe_ordered_login_methods
                                if not is_fake_email(cast(str, lm.email))
                                and lm.verified
                            ]
                        )
                        # Then we take the non-verified real emails associated with emailpassword login methods ordered by timeJoined (oldest first)
                        result.extend(
                            [
                                cast(str, lm.email)
                                for lm in recipe_ordered_login_methods
                                if not is_fake_email(cast(str, lm.email))
                                and not lm.verified
                            ]
                        )
                        # Lastly, fake emails associated with emailpassword login methods ordered by timeJoined (oldest first)
                        # We also add these into the list because they already have a password added to them so they can be a valid choice when signing in
                        # We do not want to remove the previously added "MFA password", because a new email password user was linked
                        # E.g.:
                        # 1. A discord user adds a password for MFA (which will use the fake email associated with the discord user)
                        # 2. Later they also sign up and (manually) link a full emailpassword user that they intend to use as a first factor
                        # 3. The next time they sign in using Discord, they could be asked for a secondary password.
                        # In this case, they'd be checked against the first user that they originally created for MFA, not the one later linked to the account
                        result.extend(
                            [
                                cast(str, lm.email)
                                for lm in recipe_ordered_login_methods
                                if is_fake_email(cast(str, lm.email))
                            ]
                        )
                        # We handle moving the session email to the top of the list later
                    else:
                        # This factor hasn't been set up, we list all emails belonging to the user
                        if any(
                            [
                                (lm.email is not None and not is_fake_email(lm.email))
                                for lm in ordered_login_methods
                            ]
                        ):
                            # If there is at least one real email address linked to the user, we only suggest real addresses
                            result = [
                                lm.email
                                for lm in recipe_ordered_login_methods
                                if lm.email is not None and not is_fake_email(lm.email)
                            ]
                        else:
                            # Else we use the fake ones
                            result = [
                                lm.email
                                for lm in recipe_ordered_login_methods
                                if lm.email is not None and is_fake_email(lm.email)
                            ]

                        # We handle moving the session email to the top of the list later

                        # Since in this case emails are not guaranteed to be unique, we de-duplicate the results, keeping the oldest one in the list.
                        # Using a dict keeps the original insertion order, but de-duplicates the items, Python sets are not ordered.
                        # keeping the first one added (so keeping the older one if there are two entries with the same email)
                        # e.g.: [4,2,3,2,1] -> [4,2,3,1]
                        result = list(dict.fromkeys(result))

                    # If the loginmethod associated with the session has an email address, we move it to the top of the list (if it's already in the list)
                    if (
                        session_login_method.email is not None
                        and session_login_method.email in result
                    ):
                        result = [session_login_method.email] + [
                            email
                            for email in result
                            if email != session_login_method.email
                        ]

                    # If the list is empty we generate an email address to make the flow where the user is never asked for
                    # an email address easier to implement. In many cases when the user adds an email-password factor, they
                    # actually only want to add a password and do not care about the associated email address.
                    # Custom implementations can choose to ignore this, and ask the user for the email anyway.
                    if len(result) == 0:
                        result.append(
                            f"{session_recipe_user_id.get_as_string()}@stfakeemail.supertokens.com"
                        )

                    return GetEmailsForFactorOkResult(
                        factor_id_to_emails_map={"emailpassword": result}
                    )

                mfa_instance.add_func_to_get_emails_for_factor_from_other_recipes(
                    GetEmailsForFactorFromOtherRecipesFunc(get_emails_for_factor)
                )

            mt_recipe = MultitenancyRecipe.get_instance_optional()
            if mt_recipe is not None:
                mt_recipe.all_available_first_factors.append(FactorIds.WEBAUTHN)

        PostSTInitCallbacks.add_post_init_callback(callback)

    @staticmethod
    def get_instance() -> "WebauthnRecipe":
        if WebauthnRecipe.__instance is not None:
            return WebauthnRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def get_instance_optional() -> Optional["WebauthnRecipe"]:
        return WebauthnRecipe.__instance

    @staticmethod
    def init(config: Optional[WebauthnConfig]):
        def func(app_info: AppInfo):
            if WebauthnRecipe.__instance is None:
                WebauthnRecipe.__instance = WebauthnRecipe(
                    recipe_id=WebauthnRecipe.recipe_id,
                    app_info=app_info,
                    config=config,
                    ingredients=WebauthnIngredients(email_delivery=None),
                )
                return WebauthnRecipe.__instance
            else:
                raise_general_exception(
                    "Webauthn recipe has already been initialised. Please check your code for bugs."
                )

        return func

    @staticmethod
    def reset():
        if os.environ.get("SUPERTOKENS_ENV") != "testing":
            raise_general_exception("calling testing function in non testing env")
        WebauthnRecipe.__instance = None

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(REGISTER_OPTIONS_API),
                request_id=REGISTER_OPTIONS_API,
                disabled=self.api_implementation.disable_register_options_post,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(SIGNIN_OPTIONS_API),
                request_id=SIGNIN_OPTIONS_API,
                disabled=self.api_implementation.disable_sign_in_options_post,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(SIGN_UP_API),
                request_id=SIGN_UP_API,
                disabled=self.api_implementation.disable_sign_up_post,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(SIGN_IN_API),
                request_id=SIGN_IN_API,
                disabled=self.api_implementation.disable_sign_in_post,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(
                    GENERATE_RECOVER_ACCOUNT_TOKEN_API
                ),
                request_id=GENERATE_RECOVER_ACCOUNT_TOKEN_API,
                disabled=self.api_implementation.disable_generate_recover_account_token_post,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(RECOVER_ACCOUNT_API),
                request_id=RECOVER_ACCOUNT_API,
                disabled=self.api_implementation.disable_recover_account_post,
            ),
            APIHandled(
                method="get",
                path_without_api_base_path=NormalisedURLPath(SIGNUP_EMAIL_EXISTS_API),
                request_id=SIGNUP_EMAIL_EXISTS_API,
                disabled=self.api_implementation.disable_email_exists_get,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(REGISTER_CREDENTIAL_API),
                request_id=REGISTER_CREDENTIAL_API,
                disabled=self.api_implementation.disable_register_credential_post,
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
        user_context: UserContext,
    ) -> Optional[BaseResponse]:
        from supertokens_python.recipe.webauthn.interfaces.api import APIOptions

        # APIOptions.model_rebuild()
        options = APIOptions(
            config=self.config,
            recipe_id=self.get_recipe_id(),
            recipe_implementation=self.recipe_implementation,
            req=request,
            res=response,
            email_delivery=self.email_delivery,
            app_info=self.get_app_info(),
        )

        if request_id == REGISTER_OPTIONS_API:
            return await register_options_api(
                self.api_implementation, tenant_id, options, user_context
            )

        if request_id == SIGNIN_OPTIONS_API:
            return await sign_in_options_api(
                self.api_implementation, tenant_id, options, user_context
            )

        if request_id == SIGN_UP_API:
            return await sign_up_api(
                self.api_implementation, tenant_id, options, user_context
            )

        if request_id == SIGN_IN_API:
            return await sign_in_api(
                self.api_implementation, tenant_id, options, user_context
            )

        if request_id == GENERATE_RECOVER_ACCOUNT_TOKEN_API:
            return await generate_recover_account_token_api(
                self.api_implementation, tenant_id, options, user_context
            )

        if request_id == RECOVER_ACCOUNT_API:
            return await recover_account_api(
                self.api_implementation, tenant_id, options, user_context
            )

        if request_id == SIGNUP_EMAIL_EXISTS_API:
            return await email_exists_api(
                self.api_implementation, tenant_id, options, user_context
            )

        if request_id == REGISTER_CREDENTIAL_API:
            return await register_credential_api(
                self.api_implementation, tenant_id, options, user_context
            )

        return None

    def is_error_from_this_recipe_based_on_instance(self, err: Exception):
        return isinstance(err, WebauthnError)

    async def handle_error(
        self,
        request: BaseRequest,
        err: Exception,
        response: BaseResponse,
        user_context: UserContext,
    ):
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []
