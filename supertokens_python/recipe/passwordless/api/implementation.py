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
from typing import Any, Dict, Optional, Union

from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import (
    OkResponse,
    PostAuthChecksOkResponse,
    SignInNotAllowedResponse,
    SignUpNotAllowedResponse,
    check_auth_type_and_linking_status,
    filter_out_invalid_first_factors_or_throw_if_all_are_invalid,
    get_authenticating_user_and_add_to_current_tenant_if_required,
    post_auth_checks,
    pre_auth_checks,
)
from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.passwordless.interfaces import (
    APIInterface,
    APIOptions,
    CheckCodeExpiredUserInputCodeError,
    CheckCodeIncorrectUserInputCodeError,
    CheckCodeOkResult,
    CheckCodeRestartFlowError,
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeOkResult,
    ConsumeCodePostExpiredUserInputCodeError,
    ConsumeCodePostIncorrectUserInputCodeError,
    ConsumeCodePostOkResult,
    ConsumeCodePostRestartFlowError,
    ConsumeCodeRestartFlowError,
    CreateCodePostOkResult,
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    EmailExistsGetOkResult,
    PasswordlessLoginEmailTemplateVars,
    PhoneNumberExistsGetOkResult,
    ResendCodePostOkResult,
    ResendCodePostRestartFlowError,
    SignInUpPostNotAllowedResponse,
)
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginSMSTemplateVars,
)
from supertokens_python.recipe.passwordless.utils import (
    ContactEmailOnlyConfig,
    ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig,
    get_enabled_pwless_factors,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.exceptions import UnauthorisedError
from supertokens_python.types import (
    AccountInfo,
    LoginMethod,
    RecipeUserId,
    User,
)
from supertokens_python.types.base import AccountInfoInput
from supertokens_python.types.response import GeneralErrorResponse

from ...emailverification import EmailVerificationRecipe
from ...emailverification.interfaces import CreateEmailVerificationTokenOkResult


class PasswordlessUserResult:
    user: User
    login_method: Union[LoginMethod, None]

    def __init__(self, user: User, login_method: Union[LoginMethod, None]):
        self.user = user
        self.login_method = login_method


async def get_passwordless_user_by_account_info(
    tenant_id: str,
    user_context: Dict[str, Any],
    account_info: AccountInfoInput,
) -> Optional[PasswordlessUserResult]:
    existing_users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
        tenant_id=tenant_id,
        account_info=account_info,
        do_union_of_account_info=False,
        user_context=user_context,
    )
    log_debug_message(
        f"get_passwordless_user_by_account_info got {len(existing_users)} from core resp {account_info}"
    )

    users_with_matching_login_methods = [
        PasswordlessUserResult(
            user=user,
            login_method=next(
                (
                    lm
                    for lm in user.login_methods
                    if lm.recipe_id == "passwordless"
                    and (
                        lm.has_same_email_as(account_info.email)
                        or lm.has_same_phone_number_as(account_info.phone_number)
                    )
                ),
                None,
            ),
        )
        for user in existing_users
    ]
    users_with_matching_login_methods = [
        user_data
        for user_data in users_with_matching_login_methods
        if user_data.login_method is not None
    ]

    log_debug_message(
        f"get_passwordless_user_by_account_info {len(users_with_matching_login_methods)} has matching login methods"
    )

    if len(users_with_matching_login_methods) > 1:
        raise Exception(
            "This should never happen: multiple users exist matching the accountInfo in passwordless createCode"
        )

    if len(users_with_matching_login_methods) == 0:
        return None

    return users_with_matching_login_methods[0]


class APIImplementation(APIInterface):
    async def create_code_post(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        CreateCodePostOkResult, SignInUpPostNotAllowedResponse, GeneralErrorResponse
    ]:
        error_code_map = {
            "SIGN_UP_NOT_ALLOWED": "Cannot sign in / up due to security reasons. Please try a different login method or contact support. (ERR_CODE_002)",
            "LINKING_TO_SESSION_USER_FAILED": {
                "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_019)",
            },
        }

        account_info = AccountInfoInput(
            email=email,
            phone_number=phone_number,
        )

        user_with_matching_login_method = await get_passwordless_user_by_account_info(
            tenant_id, user_context, account_info
        )

        factor_ids = []
        if session is not None:
            factor_ids = [
                FactorIds.OTP_EMAIL if email is not None else FactorIds.OTP_PHONE
            ]
        else:
            factor_ids = get_enabled_pwless_factors(api_options.config)
            if email is not None:
                factor_ids = [
                    f
                    for f in factor_ids
                    if f in [FactorIds.OTP_EMAIL, FactorIds.LINK_EMAIL]
                ]
            else:
                factor_ids = [
                    f
                    for f in factor_ids
                    if f in [FactorIds.OTP_PHONE, FactorIds.LINK_PHONE]
                ]

        is_verified_input = True
        if user_with_matching_login_method is not None:
            assert user_with_matching_login_method.login_method is not None
            is_verified_input = user_with_matching_login_method.login_method.verified

        pre_auth_checks_result = await pre_auth_checks(
            authenticating_account_info=AccountInfoWithRecipeId(
                recipe_id="passwordless",
                email=account_info.email,
                phone_number=account_info.phone_number,
            ),
            is_sign_up=user_with_matching_login_method is None,
            authenticating_user=(
                user_with_matching_login_method.user
                if user_with_matching_login_method
                else None
            ),
            is_verified=is_verified_input,
            sign_in_verifies_login_method=True,
            skip_session_user_update_in_core=True,
            tenant_id=tenant_id,
            factor_ids=factor_ids,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if not isinstance(pre_auth_checks_result, OkResponse):
            if isinstance(pre_auth_checks_result, SignUpNotAllowedResponse):
                reason = error_code_map["SIGN_UP_NOT_ALLOWED"]
                assert isinstance(reason, str)
                return SignInUpPostNotAllowedResponse(reason)
            if isinstance(pre_auth_checks_result, SignInNotAllowedResponse):
                raise Exception("Should never come here")

            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[pre_auth_checks_result.reason]
            return SignInUpPostNotAllowedResponse(reason=reason)

        user_input_code = None
        if api_options.config.get_custom_user_input_code is not None:
            user_input_code = await api_options.config.get_custom_user_input_code(
                tenant_id, user_context
            )

        user_input_code_input = user_input_code
        if api_options.config.get_custom_user_input_code is not None:
            user_input_code_input = await api_options.config.get_custom_user_input_code(
                tenant_id, user_context
            )
        response = await api_options.recipe_implementation.create_code(
            email=account_info.email,
            phone_number=account_info.phone_number,
            user_input_code=user_input_code_input,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        magic_link = None
        user_input_code = None
        flow_type = api_options.config.flow_type

        if all(
            _id.startswith("link") for _id in pre_auth_checks_result.valid_factor_ids
        ):
            flow_type = "MAGIC_LINK"
        elif all(
            _id.startswith("otp") for _id in pre_auth_checks_result.valid_factor_ids
        ):
            flow_type = "USER_INPUT_CODE"
        else:
            flow_type = "USER_INPUT_CODE_AND_MAGIC_LINK"

        if flow_type in ("MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"):
            magic_link = (
                api_options.app_info.get_origin(
                    api_options.request, user_context
                ).get_as_string_dangerous()
                + api_options.app_info.website_base_path.get_as_string_dangerous()
                + "/verify"
                + "?preAuthSessionId="
                + response.pre_auth_session_id
                + "&tenantId="
                + tenant_id
                + "#"
                + response.link_code
            )
        if flow_type in ("USER_INPUT_CODE", "USER_INPUT_CODE_AND_MAGIC_LINK"):
            user_input_code = response.user_input_code

        if isinstance(api_options.config.contact_config, ContactEmailOnlyConfig) or (
            isinstance(api_options.config.contact_config, ContactEmailOrPhoneConfig)
            and email is not None
        ):
            if email is None:
                raise Exception("Should never come here")

            log_debug_message("Sending passwordless login email to %s", email)
            passwordless_email_delivery_input = PasswordlessLoginEmailTemplateVars(
                email=email,
                user_input_code=user_input_code,
                url_with_link_code=magic_link,
                code_life_time=response.code_life_time,
                pre_auth_session_id=response.pre_auth_session_id,
                tenant_id=tenant_id,
                is_first_factor=pre_auth_checks_result.is_first_factor,
            )
            await api_options.email_delivery.ingredient_interface_impl.send_email(
                passwordless_email_delivery_input, user_context
            )
        elif isinstance(
            api_options.config.contact_config,
            (ContactEmailOrPhoneConfig, ContactPhoneOnlyConfig),
        ):
            if phone_number is None:
                raise Exception("Should never come here")
            log_debug_message("Sending passwordless login SMS to %s", phone_number)
            sms_input = PasswordlessLoginSMSTemplateVars(
                phone_number=phone_number,
                user_input_code=user_input_code,
                url_with_link_code=magic_link,
                code_life_time=response.code_life_time,
                pre_auth_session_id=response.pre_auth_session_id,
                tenant_id=tenant_id,
                is_first_factor=pre_auth_checks_result.is_first_factor,
            )
            await api_options.sms_delivery.ingredient_interface_impl.send_sms(
                sms_input, user_context
            )

        return CreateCodePostOkResult(
            response.device_id, response.pre_auth_session_id, flow_type
        )

    async def resend_code_post(
        self,
        device_id: str,
        pre_auth_session_id: str,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ResendCodePostOkResult, ResendCodePostRestartFlowError, GeneralErrorResponse
    ]:
        device_info = await api_options.recipe_implementation.list_codes_by_device_id(
            device_id=device_id, tenant_id=tenant_id, user_context=user_context
        )

        if device_info is None:
            return ResendCodePostRestartFlowError()

        if (
            api_options.config.contact_config.contact_method == "PHONE"
            and device_info.phone_number is None
        ) or (
            api_options.config.contact_config.contact_method == "EMAIL"
            and device_info.email is None
        ):
            return ResendCodePostRestartFlowError()

        user_with_matching_login_method = await get_passwordless_user_by_account_info(
            tenant_id=tenant_id,
            user_context=user_context,
            account_info=AccountInfoInput(
                email=device_info.email,
                phone_number=device_info.phone_number,
            ),
        )

        auth_type_info = await check_auth_type_and_linking_status(
            session=session,
            account_info=AccountInfoWithRecipeId(
                recipe_id="passwordless",
                email=device_info.email,
                phone_number=device_info.phone_number,
            ),
            input_user=(
                user_with_matching_login_method.user
                if user_with_matching_login_method
                else None
            ),
            skip_session_user_update_in_core=True,
            user_context=user_context,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if auth_type_info.status == "LINKING_TO_SESSION_USER_FAILED":
            return ResendCodePostRestartFlowError()

        number_of_tries_to_create_new_code = 0
        while True:
            number_of_tries_to_create_new_code += 1
            user_input_code = None
            if api_options.config.get_custom_user_input_code is not None:
                user_input_code = await api_options.config.get_custom_user_input_code(
                    tenant_id, user_context
                )
            user_input_code_input = user_input_code
            if api_options.config.get_custom_user_input_code is not None:
                user_input_code_input = (
                    await api_options.config.get_custom_user_input_code(
                        tenant_id, user_context
                    )
                )
            response = (
                await api_options.recipe_implementation.create_new_code_for_device(
                    device_id=device_id,
                    user_input_code=user_input_code_input,
                    tenant_id=tenant_id,
                    user_context=user_context,
                )
            )

            if isinstance(
                response, CreateNewCodeForDeviceUserInputCodeAlreadyUsedError
            ):
                if number_of_tries_to_create_new_code >= 3:
                    return GeneralErrorResponse(
                        "Failed to generate a one time code. Please try again"
                    )
                continue

            if isinstance(response, CreateNewCodeForDeviceOkResult):
                magic_link = None
                user_input_code = None

                factor_ids = []
                if session is not None:
                    factor_ids = [
                        (
                            FactorIds.OTP_EMAIL
                            if device_info.email is not None
                            else FactorIds.OTP_PHONE
                        )
                    ]
                else:
                    factor_ids = get_enabled_pwless_factors(api_options.config)
                    factor_ids = await filter_out_invalid_first_factors_or_throw_if_all_are_invalid(
                        factor_ids, tenant_id, False, user_context
                    )

                flow_type = api_options.config.flow_type
                if all(id.startswith("link") for id in factor_ids):
                    flow_type = "MAGIC_LINK"
                elif all(id.startswith("otp") for id in factor_ids):
                    flow_type = "USER_INPUT_CODE"
                else:
                    flow_type = "USER_INPUT_CODE_AND_MAGIC_LINK"

                if flow_type in ("MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"):
                    magic_link = (
                        api_options.app_info.get_origin(
                            api_options.request, user_context
                        ).get_as_string_dangerous()
                        + api_options.app_info.website_base_path.get_as_string_dangerous()
                        + "/verify"
                        + "?preAuthSessionId="
                        + response.pre_auth_session_id
                        + "&tenantId="
                        + tenant_id
                        + "#"
                        + response.link_code
                    )
                if flow_type in ("USER_INPUT_CODE", "USER_INPUT_CODE_AND_MAGIC_LINK"):
                    user_input_code = response.user_input_code

                if api_options.config.contact_config.contact_method == "PHONE" or (
                    api_options.config.contact_config.contact_method == "EMAIL_OR_PHONE"
                    and device_info.phone_number is not None
                ):
                    log_debug_message(
                        "Sending passwordless login SMS to %s", device_info.phone_number
                    )
                    assert device_info.phone_number is not None
                    sms_input = PasswordlessLoginSMSTemplateVars(
                        phone_number=device_info.phone_number,
                        user_input_code=user_input_code,
                        url_with_link_code=magic_link,
                        code_life_time=response.code_life_time,
                        pre_auth_session_id=response.pre_auth_session_id,
                        tenant_id=tenant_id,
                        is_first_factor=auth_type_info.is_first_factor,
                    )
                    await api_options.sms_delivery.ingredient_interface_impl.send_sms(
                        sms_input, user_context
                    )
                else:
                    log_debug_message(
                        "Sending passwordless login email to %s", device_info.email
                    )
                    assert device_info.email is not None
                    passwordless_email_delivery_input = (
                        PasswordlessLoginEmailTemplateVars(
                            email=device_info.email,
                            user_input_code=user_input_code,
                            url_with_link_code=magic_link,
                            code_life_time=response.code_life_time,
                            pre_auth_session_id=response.pre_auth_session_id,
                            tenant_id=tenant_id,
                            is_first_factor=auth_type_info.is_first_factor,
                        )
                    )
                    await (
                        api_options.email_delivery.ingredient_interface_impl.send_email(
                            passwordless_email_delivery_input, user_context
                        )
                    )

                return ResendCodePostOkResult()

            return ResendCodePostRestartFlowError()

    async def consume_code_post(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodePostOkResult,
        ConsumeCodePostRestartFlowError,
        GeneralErrorResponse,
        ConsumeCodePostIncorrectUserInputCodeError,
        ConsumeCodePostExpiredUserInputCodeError,
        SignInUpPostNotAllowedResponse,
    ]:
        error_code_map = {
            "SIGN_UP_NOT_ALLOWED": "Cannot sign in / up due to security reasons. Please try a different login method or contact support. (ERR_CODE_002)",
            "SIGN_IN_NOT_ALLOWED": "Cannot sign in / up due to security reasons. Please try a different login method or contact support. (ERR_CODE_003)",
            "LINKING_TO_SESSION_USER_FAILED": {
                "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_017)",
                "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_018)",
                "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_019)",
            },
        }

        device_info = (
            await api_options.recipe_implementation.list_codes_by_pre_auth_session_id(
                tenant_id=tenant_id,
                pre_auth_session_id=pre_auth_session_id,
                user_context=user_context,
            )
        )

        if not device_info:
            return ConsumeCodePostRestartFlowError()

        recipe_id = "passwordless"
        account_info = AccountInfo(
            phone_number=device_info.phone_number, email=device_info.email
        )

        check_credentials_response: Optional[
            Union[
                CheckCodeOkResult,
                CheckCodeIncorrectUserInputCodeError,
                CheckCodeExpiredUserInputCodeError,
                CheckCodeRestartFlowError,
            ]
        ] = None

        async def check_credentials(_: str):
            nonlocal check_credentials_response
            if check_credentials_response is None:
                check_credentials_response = (
                    await api_options.recipe_implementation.check_code(
                        pre_auth_session_id=pre_auth_session_id,
                        device_id=device_id,
                        user_input_code=user_input_code,
                        link_code=link_code,
                        tenant_id=tenant_id,
                        user_context=user_context,
                    )
                )
            return isinstance(check_credentials_response, CheckCodeOkResult)

        check_credentials_response = None
        authenticating_user = (
            await get_authenticating_user_and_add_to_current_tenant_if_required(
                email=account_info.email,
                phone_number=account_info.phone_number,
                third_party=None,
                recipe_id=recipe_id,
                user_context=user_context,
                session=session,
                tenant_id=tenant_id,
                check_credentials_on_tenant=check_credentials,
            )
        )

        ev_instance = EmailVerificationRecipe.get_instance_optional()
        if account_info.email and session and ev_instance:
            session_user = await get_user(session.get_user_id(), user_context)
            if session_user is None:
                raise UnauthorisedError(
                    "Session user not found",
                )

            login_method = next(
                (
                    lm
                    for lm in session_user.login_methods
                    if lm.recipe_user_id.get_as_string()
                    == session.get_recipe_user_id().get_as_string()
                ),
                None,
            )
            if login_method is None:
                raise UnauthorisedError(
                    "Session user and session recipeUserId is inconsistent",
                )

            if (
                login_method.has_same_email_as(account_info.email)
                and not login_method.verified
            ):
                if await check_credentials(tenant_id):
                    token_response = await ev_instance.recipe_implementation.create_email_verification_token(
                        tenant_id=tenant_id,
                        recipe_user_id=login_method.recipe_user_id,
                        email=account_info.email,
                        user_context=user_context,
                    )
                    if isinstance(token_response, CreateEmailVerificationTokenOkResult):
                        await (
                            ev_instance.recipe_implementation.verify_email_using_token(
                                tenant_id=tenant_id,
                                token=token_response.token,
                                attempt_account_linking=False,
                                user_context=user_context,
                            )
                        )

        factor_id = (
            FactorIds.OTP_EMAIL
            if device_info.email and user_input_code
            else (
                FactorIds.LINK_EMAIL
                if device_info.email
                else (FactorIds.OTP_PHONE if user_input_code else FactorIds.LINK_PHONE)
            )
        )

        is_sign_up = authenticating_user is None
        pre_auth_checks_result = await pre_auth_checks(
            authenticating_account_info=AccountInfoWithRecipeId(
                recipe_id="passwordless",
                email=device_info.email,
                phone_number=device_info.phone_number,
            ),
            factor_ids=[factor_id],
            authenticating_user=(
                authenticating_user.user if authenticating_user else None
            ),
            is_sign_up=is_sign_up,
            is_verified=(
                authenticating_user.login_method.verified
                if authenticating_user and authenticating_user.login_method
                else True
            ),
            sign_in_verifies_login_method=True,
            skip_session_user_update_in_core=False,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if not isinstance(pre_auth_checks_result, OkResponse):
            if isinstance(pre_auth_checks_result, SignUpNotAllowedResponse):
                reason = error_code_map["SIGN_UP_NOT_ALLOWED"]
                assert isinstance(reason, str)
                return SignInUpPostNotAllowedResponse(reason)
            if isinstance(pre_auth_checks_result, SignInNotAllowedResponse):
                reason = error_code_map["SIGN_IN_NOT_ALLOWED"]
                assert isinstance(reason, str)
                return SignInUpPostNotAllowedResponse(reason)

            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[pre_auth_checks_result.reason]
            return SignInUpPostNotAllowedResponse(reason=reason)

        if check_credentials_response is not None:
            if not isinstance(check_credentials_response, CheckCodeOkResult):
                return check_credentials_response

        response = await api_options.recipe_implementation.consume_code(
            pre_auth_session_id=pre_auth_session_id,
            device_id=device_id,
            user_input_code=user_input_code,
            link_code=link_code,
            session=session,
            tenant_id=tenant_id,
            user_context=user_context,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if isinstance(response, ConsumeCodeRestartFlowError):
            return ConsumeCodePostRestartFlowError()
        if isinstance(response, ConsumeCodeIncorrectUserInputCodeError):
            return ConsumeCodePostIncorrectUserInputCodeError(
                response.failed_code_input_attempt_count,
                response.maximum_code_input_attempts,
            )
        if isinstance(response, ConsumeCodeExpiredUserInputCodeError):
            return ConsumeCodePostExpiredUserInputCodeError(
                response.failed_code_input_attempt_count,
                response.maximum_code_input_attempts,
            )
        if not isinstance(response, ConsumeCodeOkResult):
            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[response.reason]
            return SignInUpPostNotAllowedResponse(reason=reason)

        authenticating_user_input: User
        if response.user:
            authenticating_user_input = response.user
        elif authenticating_user:
            authenticating_user_input = authenticating_user.user
        else:
            raise Exception("Should never come here")
        recipe_user_id_input: RecipeUserId
        if response.recipe_user_id:
            recipe_user_id_input = response.recipe_user_id
        elif authenticating_user:
            assert authenticating_user.login_method is not None
            recipe_user_id_input = authenticating_user.login_method.recipe_user_id
        else:
            raise Exception("Should never come here")

        post_auth_checks_result = await post_auth_checks(
            factor_id=factor_id,
            is_sign_up=is_sign_up,
            authenticated_user=authenticating_user_input,
            recipe_user_id=recipe_user_id_input,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            request=api_options.request,
        )

        if not isinstance(post_auth_checks_result, PostAuthChecksOkResponse):
            reason = error_code_map["SIGN_IN_NOT_ALLOWED"]
            assert isinstance(reason, str)
            return SignInUpPostNotAllowedResponse(reason)

        return ConsumeCodePostOkResult(
            created_new_recipe_user=response.created_new_recipe_user,
            user=post_auth_checks_result.user,
            session=post_auth_checks_result.session,
        )

    async def email_exists_get(
        self,
        email: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailExistsGetOkResult, GeneralErrorResponse]:
        users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(email=email),
            do_union_of_account_info=False,
            user_context=user_context,
        )
        user_exists = any(
            any(
                lm.recipe_id == "passwordless" and lm.has_same_email_as(email)
                for lm in u.login_methods
            )
            for u in users
        )

        return EmailExistsGetOkResult(exists=user_exists)

    async def phone_number_exists_get(
        self,
        phone_number: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[PhoneNumberExistsGetOkResult, GeneralErrorResponse]:
        users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(phone_number=phone_number),
            do_union_of_account_info=False,
            user_context=user_context,
        )
        return PhoneNumberExistsGetOkResult(exists=len(users) > 0)
