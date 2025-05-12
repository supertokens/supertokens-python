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
from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.auth_utils import is_fake_email
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.emailpassword.types import (
    EmailPasswordIngredients,
    EmailTemplateVars,
)
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
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.types import RecipeUserId, User

from ...post_init_callbacks import PostSTInitCallbacks
from .api.implementation import APIImplementation
from .exceptions import FieldError, SuperTokensEmailPasswordError
from .interfaces import APIOptions
from .recipe_implementation import RecipeImplementation

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.querier import Querier

from .api import (
    handle_email_exists_api,
    handle_generate_password_reset_token_api,
    handle_password_reset_api,
    handle_sign_in_api,
    handle_sign_up_api,
)
from .constants import (
    SIGNIN,
    SIGNUP,
    SIGNUP_EMAIL_EXISTS,
    SIGNUP_EMAIL_EXISTS_OLD,
    USER_PASSWORD_RESET,
    USER_PASSWORD_RESET_TOKEN,
)
from .utils import (
    InputOverrideConfig,
    InputSignUpFeature,
    validate_and_normalise_user_input,
)


class EmailPasswordRecipe(RecipeModule):
    recipe_id = "emailpassword"
    __instance = None
    email_delivery: EmailDeliveryIngredient[EmailTemplateVars]

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        ingredients: EmailPasswordIngredients,
        sign_up_feature: Union[InputSignUpFeature, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            app_info,
            sign_up_feature,
            override,
            email_delivery,
        )

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config
        )
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        email_delivery_ingredient = ingredients.email_delivery
        if email_delivery_ingredient is None:
            self.email_delivery = EmailDeliveryIngredient(
                self.config.get_email_delivery_config(self.recipe_implementation)
            )
        else:
            self.email_delivery = email_delivery_ingredient

        api_implementation = APIImplementation()
        self.api_implementation = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

        def callback():
            mfa_instance = MultiFactorAuthRecipe.get_instance()
            if mfa_instance is not None:

                async def f1(_: TenantConfig):
                    return ["emailpassword"]

                mfa_instance.add_func_to_get_all_available_secondary_factor_ids_from_other_recipes(
                    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc(f1)
                )

                async def get_factors_setup_for_user(
                    user: User, _: Dict[str, Any]
                ) -> List[str]:
                    for login_method in user.login_methods:
                        # We don't check for tenant_id here because if we find the user
                        # with emailpassword login_method from different tenant, then
                        # we assume the factor is setup for this user. And as part of factor
                        # completion, we associate that login_method with the session's tenant_id
                        if login_method.recipe_id == EmailPasswordRecipe.recipe_id:
                            return ["emailpassword"]
                    return []

                mfa_instance.add_func_to_get_factors_setup_for_user_from_other_recipes(
                    GetFactorsSetupForUserFromOtherRecipesFunc(
                        get_factors_setup_for_user
                    )
                )

                async def get_emails_for_factor(
                    user: User, session_recipe_user_id: RecipeUserId
                ) -> Union[
                    GetEmailsForFactorOkResult,
                    GetEmailsForFactorUnknownSessionRecipeUserIdResult,
                ]:
                    # This function is called in the MFA info endpoint API.
                    # Based on https://github.com/supertokens/supertokens-node/pull/741#discussion_r1432749346

                    # preparing some reusable variables for the logic below...
                    session_login_method = next(
                        (
                            lm
                            for lm in user.login_methods
                            if lm.recipe_user_id.get_as_string()
                            == session_recipe_user_id.get_as_string()
                        ),
                        None,
                    )
                    if session_login_method is None:
                        return GetEmailsForFactorUnknownSessionRecipeUserIdResult()

                    # We order the login methods based on time_joined (oldest first)
                    ordered_login_methods = sorted(
                        user.login_methods, key=lambda lm: lm.time_joined
                    )
                    # Then we take the ones that belong to this recipe
                    recipe_login_methods = [
                        lm
                        for lm in ordered_login_methods
                        if lm.recipe_id == EmailPasswordRecipe.recipe_id
                    ]

                    if recipe_login_methods:
                        # If there are login methods belonging to this recipe, the factor is set up
                        # In this case we only list email addresses that have a password associated with them
                        result = (
                            # First we take the verified real emails associated with emailpassword login methods ordered by time_joined (oldest first)
                            [
                                lm.email
                                for lm in recipe_login_methods
                                if lm.email
                                and not is_fake_email(lm.email)
                                and lm.verified
                            ]
                            +
                            # Then we take the non-verified real emails associated with emailpassword login methods ordered by time_joined (oldest first)
                            [
                                lm.email
                                for lm in recipe_login_methods
                                if lm.email
                                and not is_fake_email(lm.email)
                                and not lm.verified
                            ]
                            +
                            # Lastly, fake emails associated with emailpassword login methods ordered by time_joined (oldest first)
                            [
                                lm.email
                                for lm in recipe_login_methods
                                if lm.email and is_fake_email(lm.email)
                            ]
                        )
                    else:
                        # This factor hasn't been set up, we list all emails belonging to the user
                        if any(
                            lm.email and not is_fake_email(lm.email)
                            for lm in ordered_login_methods
                        ):
                            # If there is at least one real email address linked to the user, we only suggest real addresses
                            result = [
                                lm.email
                                for lm in ordered_login_methods
                                if lm.email and not is_fake_email(lm.email)
                            ]
                        else:
                            # Else we use the fake ones
                            result = [
                                lm.email
                                for lm in ordered_login_methods
                                if lm.email and is_fake_email(lm.email)
                            ]

                        # Since in this case emails are not guaranteed to be unique, we de-duplicate the results, keeping the oldest one in the list.
                        result = list(dict.fromkeys(result))

                    # If the login_method associated with the session has an email address, we move it to the top of the list (if it's already in the list)
                    if (
                        session_login_method.email
                        and session_login_method.email in result
                    ):
                        result.remove(session_login_method.email)
                        result.insert(0, session_login_method.email)

                    # If the list is empty we generate an email address to make the flow where the user is never asked for
                    # an email address easier to implement.
                    if not result:
                        result.append(
                            f"{session_recipe_user_id}@stfakeemail.supertokens.com"
                        )

                    return GetEmailsForFactorOkResult(
                        factor_id_to_emails_map={"emailpassword": result}
                    )

                mfa_instance.add_func_to_get_emails_for_factor_from_other_recipes(
                    GetEmailsForFactorFromOtherRecipesFunc(get_emails_for_factor)
                )

            mt_recipe = MultitenancyRecipe.get_instance_optional()
            if mt_recipe is not None:
                mt_recipe.all_available_first_factors.append(FactorIds.EMAILPASSWORD)

        PostSTInitCallbacks.add_post_init_callback(callback)

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensEmailPasswordError)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                NormalisedURLPath(SIGNUP),
                "post",
                SIGNUP,
                self.api_implementation.disable_sign_up_post,
            ),
            APIHandled(
                NormalisedURLPath(SIGNIN),
                "post",
                SIGNIN,
                self.api_implementation.disable_sign_in_post,
            ),
            APIHandled(
                NormalisedURLPath(USER_PASSWORD_RESET_TOKEN),
                "post",
                USER_PASSWORD_RESET_TOKEN,
                self.api_implementation.disable_generate_password_reset_token_post,
            ),
            APIHandled(
                NormalisedURLPath(USER_PASSWORD_RESET),
                "post",
                USER_PASSWORD_RESET,
                self.api_implementation.disable_password_reset_post,
            ),
            APIHandled(
                NormalisedURLPath(SIGNUP_EMAIL_EXISTS_OLD),
                "get",
                SIGNUP_EMAIL_EXISTS_OLD,
                self.api_implementation.disable_email_exists_get,
            ),
            APIHandled(
                NormalisedURLPath(SIGNUP_EMAIL_EXISTS),
                "get",
                SIGNUP_EMAIL_EXISTS,
                self.api_implementation.disable_email_exists_get,
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
    ):
        api_options = APIOptions(
            request,
            response,
            self.recipe_id,
            self.config,
            self.recipe_implementation,
            self.get_app_info(),
            self.email_delivery,
        )
        if request_id == SIGNUP:
            return await handle_sign_up_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id == SIGNIN:
            return await handle_sign_in_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id in (SIGNUP_EMAIL_EXISTS, SIGNUP_EMAIL_EXISTS_OLD):
            return await handle_email_exists_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id == USER_PASSWORD_RESET_TOKEN:
            return await handle_generate_password_reset_token_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id == USER_PASSWORD_RESET:
            return await handle_password_reset_api(
                tenant_id, self.api_implementation, api_options, user_context
            )

        return None

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        if isinstance(err, SuperTokensEmailPasswordError):
            if isinstance(err, FieldError):
                response.set_json_content(
                    {"status": "FIELD_ERROR", "formFields": err.get_json_form_fields()}
                )
                return response
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(
        sign_up_feature: Union[InputSignUpFeature, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    ):
        def func(app_info: AppInfo):
            if EmailPasswordRecipe.__instance is None:
                ingredients = EmailPasswordIngredients(None)
                EmailPasswordRecipe.__instance = EmailPasswordRecipe(
                    EmailPasswordRecipe.recipe_id,
                    app_info,
                    ingredients,
                    sign_up_feature,
                    override,
                    email_delivery=email_delivery,
                )
                return EmailPasswordRecipe.__instance
            raise Exception(
                None,
                "Emailpassword recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def get_instance() -> EmailPasswordRecipe:
        if EmailPasswordRecipe.__instance is not None:
            return EmailPasswordRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        EmailPasswordRecipe.__instance = None
