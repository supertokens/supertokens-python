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

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.emailpassword.types import (
    EmailPasswordIngredients,
    EmailTemplateVars,
)
from supertokens_python.recipe_module import APIHandled, RecipeModule
from ..emailverification.interfaces import (
    UnknownUserIdError,
    GetEmailForUserIdOkResult,
    EmailDoesNotExistError,
)

from .api.implementation import APIImplementation
from .exceptions import FieldError, SuperTokensEmailPasswordError
from .interfaces import APIOptions
from .recipe_implementation import RecipeImplementation
from ...post_init_callbacks import PostSTInitCallbacks

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.querier import Querier
from supertokens_python.recipe.emailverification import EmailVerificationRecipe

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
    USER_PASSWORD_RESET,
    USER_PASSWORD_RESET_TOKEN,
)
from .utils import (
    InputOverrideConfig,
    InputResetPasswordUsingTokenFeature,
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
        reset_password_using_token_feature: Union[
            InputResetPasswordUsingTokenFeature, None
        ] = None,
        override: Union[InputOverrideConfig, None] = None,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            app_info,
            sign_up_feature,
            reset_password_using_token_feature,
            override,
            email_delivery,
        )
        recipe_implementation = RecipeImplementation(Querier.get_instance(recipe_id))
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
            ev_recipe = EmailVerificationRecipe.get_instance_optional()
            if ev_recipe:
                ev_recipe.add_get_email_for_user_id_func(self.get_email_for_user_id)

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
                NormalisedURLPath(SIGNUP_EMAIL_EXISTS),
                "get",
                SIGNUP_EMAIL_EXISTS,
                self.api_implementation.disable_email_exists_get,
            ),
        ]

    async def handle_api_request(
        self,
        request_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
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
            return await handle_sign_up_api(self.api_implementation, api_options)
        if request_id == SIGNIN:
            return await handle_sign_in_api(self.api_implementation, api_options)
        if request_id == SIGNUP_EMAIL_EXISTS:
            return await handle_email_exists_api(self.api_implementation, api_options)
        if request_id == USER_PASSWORD_RESET_TOKEN:
            return await handle_generate_password_reset_token_api(
                self.api_implementation, api_options
            )
        if request_id == USER_PASSWORD_RESET:
            return await handle_password_reset_api(self.api_implementation, api_options)

        return None

    async def handle_error(
        self, request: BaseRequest, err: SuperTokensError, response: BaseResponse
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
        reset_password_using_token_feature: Union[
            InputResetPasswordUsingTokenFeature, None
        ] = None,
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
                    reset_password_using_token_feature,
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

    # instance functions below...............

    async def get_email_for_user_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[UnknownUserIdError, GetEmailForUserIdOkResult, EmailDoesNotExistError]:
        user_info = await self.recipe_implementation.get_user_by_id(
            user_id, user_context
        )
        if user_info is not None:
            return GetEmailForUserIdOkResult(user_info.email)

        return UnknownUserIdError()
