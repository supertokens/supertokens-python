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

from supertokens_python.auth_utils import is_fake_email
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.ingredients.smsdelivery import SMSDeliveryIngredient
from supertokens_python.querier import Querier
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multifactorauth.types import (
    FactorIds,
    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc,
    GetEmailsForFactorFromOtherRecipesFunc,
    GetEmailsForFactorOkResult,
    GetEmailsForFactorUnknownSessionRecipeUserIdResult,
    GetFactorsSetupForUserFromOtherRecipesFunc,
    GetPhoneNumbersForFactorsFromOtherRecipesFunc,
    GetPhoneNumbersForFactorsOkResult,
    GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.passwordless.types import (
    PasswordlessIngredients,
    PasswordlessLoginSMSTemplateVars,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import RecipeUserId, User

from ...post_init_callbacks import PostSTInitCallbacks
from .api import (
    consume_code,
    create_code,
    email_exists,
    phone_number_exists,
    resend_code,
)
from .api.implementation import APIImplementation
from .constants import (
    CONSUME_CODE_API,
    CREATE_CODE_API,
    DOES_EMAIL_EXIST_API,
    DOES_EMAIL_EXIST_API_OLD,
    DOES_PHONE_NUMBER_EXIST_API,
    DOES_PHONE_NUMBER_EXIST_API_OLD,
    RESEND_CODE_API,
)
from .exceptions import SuperTokensPasswordlessError
from .interfaces import (
    APIOptions,
    ConsumeCodeOkResult,
    PasswordlessLoginEmailTemplateVars,
    RecipeInterface,
)
from .recipe_implementation import RecipeImplementation
from .utils import (
    ContactConfig,
    OverrideConfig,
    get_enabled_pwless_factors,
    validate_and_normalise_user_input,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.ingredients.smsdelivery.types import SMSDeliveryConfig
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import APIHandled, RecipeModule


class PasswordlessRecipe(RecipeModule):
    recipe_id = "passwordless"
    __instance = None
    email_delivery: EmailDeliveryIngredient[PasswordlessLoginEmailTemplateVars]
    sms_delivery: SMSDeliveryIngredient[PasswordlessLoginSMSTemplateVars]

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        contact_config: ContactConfig,
        flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ],
        ingredients: PasswordlessIngredients,
        override: Union[OverrideConfig, None] = None,
        get_custom_user_input_code: Union[
            Callable[[str, Dict[str, Any]], Awaitable[str]], None
        ] = None,
        email_delivery: Union[
            EmailDeliveryConfig[PasswordlessLoginEmailTemplateVars], None
        ] = None,
        sms_delivery: Union[
            SMSDeliveryConfig[PasswordlessLoginSMSTemplateVars], None
        ] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            app_info,
            contact_config,
            flow_type,
            override,
            get_custom_user_input_code,
            email_delivery,
            sms_delivery,
        )

        recipe_implementation = RecipeImplementation(Querier.get_instance(recipe_id))
        self.recipe_implementation: RecipeInterface = (
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

        sms_delivery_ingredient = ingredients.sms_delivery
        self.sms_delivery = (
            SMSDeliveryIngredient(self.config.get_sms_delivery_config())
            if sms_delivery_ingredient is None
            else sms_delivery_ingredient
        )

        def callback():
            mfa_instance = MultiFactorAuthRecipe.get_instance()
            all_factors = get_enabled_pwless_factors(self.config)
            if mfa_instance is not None:

                async def f1(_: TenantConfig):
                    return all_factors

                mfa_instance.add_func_to_get_all_available_secondary_factor_ids_from_other_recipes(
                    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc(f1)
                )

                async def get_factors_setup_for_user(
                    user: User, _: Dict[str, Any]
                ) -> List[str]:
                    def is_factor_setup_for_user(user: User, factor_id: str) -> bool:
                        for login_method in user.login_methods:
                            if login_method.recipe_id != "passwordless":
                                continue

                            if login_method.email is not None and not is_fake_email(
                                login_method.email
                            ):
                                if factor_id in [
                                    FactorIds.OTP_EMAIL,
                                    FactorIds.LINK_EMAIL,
                                ]:
                                    return True

                            if login_method.phone_number is not None:
                                if factor_id in [
                                    FactorIds.OTP_PHONE,
                                    FactorIds.LINK_PHONE,
                                ]:
                                    return True
                        return False

                    return [
                        factor_id
                        for factor_id in all_factors
                        if is_factor_setup_for_user(user, factor_id)
                    ]

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

                    ordered_login_methods = sorted(
                        user.login_methods, key=lambda lm: lm.time_joined
                    )

                    # MAIN LOGIC FOR THE FUNCTION STARTS HERE
                    non_fake_emails_passwordless = [
                        lm.email
                        for lm in ordered_login_methods
                        if lm.recipe_id == "passwordless"
                        and lm.email is not None
                        and not is_fake_email(lm.email)
                    ]

                    if not non_fake_emails_passwordless:
                        # This factor is not set up for email-based factors.
                        # We check for emails from other loginMethods and return those.
                        emails_result = []
                        if session_login_method.email is not None and not is_fake_email(
                            session_login_method.email
                        ):
                            emails_result = [session_login_method.email]

                        emails_result.extend(
                            [
                                lm.email
                                for lm in ordered_login_methods
                                if lm.email is not None
                                and not is_fake_email(lm.email)
                                and lm.email not in emails_result
                            ]
                        )
                        factor_id_to_emails_map = {}
                        if FactorIds.OTP_EMAIL in all_factors:
                            factor_id_to_emails_map[FactorIds.OTP_EMAIL] = emails_result
                        if FactorIds.LINK_EMAIL in all_factors:
                            factor_id_to_emails_map[FactorIds.LINK_EMAIL] = (
                                emails_result
                            )
                        return GetEmailsForFactorOkResult(
                            factor_id_to_emails_map=factor_id_to_emails_map
                        )
                    elif len(non_fake_emails_passwordless) == 1:
                        # Return just this email to avoid creating more loginMethods
                        factor_id_to_emails_map = {}
                        if FactorIds.OTP_EMAIL in all_factors:
                            factor_id_to_emails_map[FactorIds.OTP_EMAIL] = (
                                non_fake_emails_passwordless
                            )
                        if FactorIds.LINK_EMAIL in all_factors:
                            factor_id_to_emails_map[FactorIds.LINK_EMAIL] = (
                                non_fake_emails_passwordless
                            )
                        return GetEmailsForFactorOkResult(
                            factor_id_to_emails_map=factor_id_to_emails_map
                        )

                    # Return all emails with passwordless login method, prioritizing session's email
                    emails_result = []
                    if (
                        session_login_method.email is not None
                        and session_login_method.email in non_fake_emails_passwordless
                    ):
                        emails_result = [session_login_method.email]

                    emails_result.extend(
                        [
                            email
                            for email in non_fake_emails_passwordless
                            if email not in emails_result
                        ]
                    )

                    factor_id_to_emails_map: Dict[str, List[str]] = {}
                    if FactorIds.OTP_EMAIL in all_factors:
                        factor_id_to_emails_map[FactorIds.OTP_EMAIL] = emails_result
                    if FactorIds.LINK_EMAIL in all_factors:
                        factor_id_to_emails_map[FactorIds.LINK_EMAIL] = emails_result

                    return GetEmailsForFactorOkResult(
                        factor_id_to_emails_map=factor_id_to_emails_map
                    )

                mfa_instance.add_func_to_get_emails_for_factor_from_other_recipes(
                    GetEmailsForFactorFromOtherRecipesFunc(get_emails_for_factor)
                )

                async def get_phone_numbers_for_factors(
                    user: User, session_recipe_user_id: RecipeUserId
                ) -> Union[
                    GetPhoneNumbersForFactorsOkResult,
                    GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult,
                ]:
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
                        return (
                            GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult()
                        )

                    ordered_login_methods = sorted(
                        user.login_methods, key=lambda lm: lm.time_joined
                    )

                    phone_numbers = [
                        lm.phone_number
                        for lm in ordered_login_methods
                        if lm.recipe_id == "passwordless"
                        and lm.phone_number is not None
                    ]

                    if not phone_numbers:
                        phones_result = []
                        if session_login_method.phone_number is not None:
                            phones_result = [session_login_method.phone_number]

                        phones_result.extend(
                            [
                                lm.phone_number
                                for lm in ordered_login_methods
                                if lm.phone_number is not None
                                and lm.phone_number not in phones_result
                            ]
                        )
                    elif len(phone_numbers) == 1:
                        phones_result = phone_numbers
                    else:
                        phones_result = []
                        if (
                            session_login_method.phone_number is not None
                            and session_login_method.phone_number in phone_numbers
                        ):
                            phones_result = [session_login_method.phone_number]
                        phones_result.extend(
                            [
                                phone
                                for phone in phone_numbers
                                if phone not in phones_result
                            ]
                        )

                    factor_id_to_phone_number_map: Dict[str, List[str]] = {}
                    if FactorIds.OTP_PHONE in all_factors:
                        factor_id_to_phone_number_map[FactorIds.OTP_PHONE] = (
                            phones_result
                        )
                    if FactorIds.LINK_PHONE in all_factors:
                        factor_id_to_phone_number_map[FactorIds.LINK_PHONE] = (
                            phones_result
                        )

                    return GetPhoneNumbersForFactorsOkResult(
                        factor_id_to_phone_number_map=factor_id_to_phone_number_map
                    )

                mfa_instance.add_func_to_get_phone_numbers_for_factors_from_other_recipes(
                    GetPhoneNumbersForFactorsFromOtherRecipesFunc(
                        get_phone_numbers_for_factors
                    )
                )

            mt_recipe = MultitenancyRecipe.get_instance_optional()
            if mt_recipe is not None:
                for factor_id in all_factors:
                    mt_recipe.all_available_first_factors.append(factor_id)

        PostSTInitCallbacks.add_post_init_callback(callback)

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(CONSUME_CODE_API),
                request_id=CONSUME_CODE_API,
                disabled=self.api_implementation.disable_consume_code_post,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(CREATE_CODE_API),
                request_id=CREATE_CODE_API,
                disabled=self.api_implementation.disable_create_code_post,
            ),
            APIHandled(
                method="get",
                path_without_api_base_path=NormalisedURLPath(DOES_EMAIL_EXIST_API),
                request_id=DOES_EMAIL_EXIST_API,
                disabled=self.api_implementation.disable_email_exists_get,
            ),
            APIHandled(
                method="get",
                path_without_api_base_path=NormalisedURLPath(
                    DOES_PHONE_NUMBER_EXIST_API
                ),
                request_id=DOES_PHONE_NUMBER_EXIST_API,
                disabled=self.api_implementation.disable_phone_number_exists_get,
            ),
            APIHandled(
                method="get",
                path_without_api_base_path=NormalisedURLPath(DOES_EMAIL_EXIST_API_OLD),
                request_id=DOES_EMAIL_EXIST_API_OLD,
                disabled=self.api_implementation.disable_email_exists_get,
            ),
            APIHandled(
                method="get",
                path_without_api_base_path=NormalisedURLPath(
                    DOES_PHONE_NUMBER_EXIST_API_OLD
                ),
                request_id=DOES_PHONE_NUMBER_EXIST_API_OLD,
                disabled=self.api_implementation.disable_phone_number_exists_get,
            ),
            APIHandled(
                method="post",
                path_without_api_base_path=NormalisedURLPath(RESEND_CODE_API),
                request_id=RESEND_CODE_API,
                disabled=self.api_implementation.disable_resend_code_post,
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
        options = APIOptions(
            request,
            response,
            self.get_recipe_id(),
            self.config,
            self.recipe_implementation,
            self.get_app_info(),
            self.email_delivery,
            self.sms_delivery,
        )
        if request_id == CONSUME_CODE_API:
            return await consume_code(
                self.api_implementation, tenant_id, options, user_context
            )
        if request_id == CREATE_CODE_API:
            return await create_code(
                self.api_implementation, tenant_id, options, user_context
            )
        if request_id in (DOES_EMAIL_EXIST_API, DOES_EMAIL_EXIST_API_OLD):
            return await email_exists(
                self.api_implementation, tenant_id, options, user_context
            )
        if request_id in (DOES_PHONE_NUMBER_EXIST_API, DOES_PHONE_NUMBER_EXIST_API_OLD):
            return await phone_number_exists(
                self.api_implementation, tenant_id, options, user_context
            )
        return await resend_code(
            self.api_implementation, tenant_id, options, user_context
        )

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:  # type: ignore
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and isinstance(
            err, SuperTokensPasswordlessError
        )

    @staticmethod
    def init(
        contact_config: ContactConfig,
        flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ],
        override: Union[OverrideConfig, None] = None,
        get_custom_user_input_code: Union[
            Callable[[str, Dict[str, Any]], Awaitable[str]], None
        ] = None,
        email_delivery: Union[
            EmailDeliveryConfig[PasswordlessLoginEmailTemplateVars], None
        ] = None,
        sms_delivery: Union[
            SMSDeliveryConfig[PasswordlessLoginSMSTemplateVars], None
        ] = None,
    ):
        def func(app_info: AppInfo):
            if PasswordlessRecipe.__instance is None:
                ingredients = PasswordlessIngredients(None, None)
                PasswordlessRecipe.__instance = PasswordlessRecipe(
                    PasswordlessRecipe.recipe_id,
                    app_info,
                    contact_config,
                    flow_type,
                    ingredients,
                    override,
                    get_custom_user_input_code,
                    email_delivery,
                    sms_delivery,
                )
                return PasswordlessRecipe.__instance
            raise_general_exception(
                "Passwordless recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> PasswordlessRecipe:
        if PasswordlessRecipe.__instance is not None:
            return PasswordlessRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        PasswordlessRecipe.__instance = None

    async def create_magic_link(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        tenant_id: str,
        request: Optional[BaseRequest],
        user_context: Dict[str, Any],
    ) -> str:
        user_input_code = None
        if self.config.get_custom_user_input_code is not None:
            user_input_code = await self.config.get_custom_user_input_code(
                tenant_id, user_context
            )

        code_info = await self.recipe_implementation.create_code(
            email=email,
            phone_number=phone_number,
            tenant_id=tenant_id,
            user_input_code=user_input_code,
            user_context=user_context,
            session=None,
            should_try_linking_with_session_user=False,
        )

        app_info = self.get_app_info()

        magic_link = (
            app_info.get_origin(request, user_context).get_as_string_dangerous()
            + app_info.website_base_path.get_as_string_dangerous()
            + "/verify"
            + "?preAuthSessionId="
            + code_info.pre_auth_session_id
            + "&tenantId="
            + tenant_id
            + "#"
            + code_info.link_code
        )
        return magic_link

    async def signinup(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        session: Optional[SessionContainer],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> ConsumeCodeOkResult:
        code_info = await self.recipe_implementation.create_code(
            email=email,
            phone_number=phone_number,
            user_input_code=None,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=False,
        )
        consume_code_result = await self.recipe_implementation.consume_code(
            link_code=code_info.link_code,
            pre_auth_session_id=code_info.pre_auth_session_id,
            device_id=code_info.device_id,
            user_input_code=code_info.user_input_code,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=False,
        )
        if isinstance(consume_code_result, ConsumeCodeOkResult):
            return consume_code_result
        raise Exception("Failed to create user. Please retry")
