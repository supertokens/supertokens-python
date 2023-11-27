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
from typing import Any, Dict, Union

from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.passwordless.interfaces import (
    APIInterface,
    APIOptions,
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
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
)
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginSMSTemplateVars,
)
from supertokens_python.recipe.passwordless.utils import (
    ContactEmailOnlyConfig,
    ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig,
)
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.types import GeneralErrorResponse
from ...emailverification import EmailVerificationRecipe
from ...emailverification.interfaces import CreateEmailVerificationTokenOkResult


class APIImplementation(APIInterface):
    async def create_code_post(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[CreateCodePostOkResult, GeneralErrorResponse]:
        user_input_code = None
        if api_options.config.get_custom_user_input_code is not None:
            user_input_code = await api_options.config.get_custom_user_input_code(
                tenant_id, user_context
            )
        response = await api_options.recipe_implementation.create_code(
            email, phone_number, user_input_code, tenant_id, user_context
        )
        magic_link = None
        user_input_code = None
        flow_type = api_options.config.flow_type
        if flow_type in ("MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"):
            magic_link = (
                api_options.app_info.get_origin(
                    api_options.request, user_context
                ).get_as_string_dangerous()
                + api_options.app_info.website_base_path.get_as_string_dangerous()
                + "/verify"
                + "?rid="
                + api_options.recipe_id
                + "&preAuthSessionId="
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
            isinstance(api_options.config.contact_config, ContactEmailOnlyConfig)
            and device_info.email is None
        ) or (
            isinstance(api_options.config.contact_config, ContactPhoneOnlyConfig)
            and device_info.phone_number is None
        ):
            return ResendCodePostRestartFlowError()
        number_of_tries_to_create_new_code = 0
        while True:
            number_of_tries_to_create_new_code += 1
            user_input_code = None
            if api_options.config.get_custom_user_input_code is not None:
                user_input_code = await api_options.config.get_custom_user_input_code(
                    tenant_id, user_context
                )
            response = (
                await api_options.recipe_implementation.create_new_code_for_device(
                    device_id=device_id,
                    user_input_code=user_input_code,
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
                flow_type = api_options.config.flow_type
                if flow_type in ("MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"):
                    magic_link = (
                        api_options.app_info.get_origin(
                            api_options.request, user_context
                        ).get_as_string_dangerous()
                        + api_options.app_info.website_base_path.get_as_string_dangerous()
                        + "/verify"
                        + "?rid="
                        + api_options.recipe_id
                        + "&preAuthSessionId="
                        + response.pre_auth_session_id
                        + "&tenantId="
                        + tenant_id
                        + "#"
                        + response.link_code
                    )
                if flow_type in ("USER_INPUT_CODE", "USER_INPUT_CODE_AND_MAGIC_LINK"):
                    user_input_code = response.user_input_code

                if isinstance(
                    api_options.config.contact_config, ContactEmailOnlyConfig
                ) or (
                    isinstance(
                        api_options.config.contact_config, ContactEmailOrPhoneConfig
                    )
                    and device_info.email is not None
                ):
                    if device_info.email is None:
                        raise Exception("Should never come here")

                    log_debug_message(
                        "Sending passwordless login email to %s", device_info.email
                    )
                    passwordless_email_delivery_input = (
                        PasswordlessLoginEmailTemplateVars(
                            email=device_info.email,
                            user_input_code=user_input_code,
                            url_with_link_code=magic_link,
                            code_life_time=response.code_life_time,
                            pre_auth_session_id=response.pre_auth_session_id,
                            tenant_id=tenant_id,
                        )
                    )
                    await api_options.email_delivery.ingredient_interface_impl.send_email(
                        passwordless_email_delivery_input, user_context
                    )
                elif isinstance(
                    api_options.config.contact_config,
                    (ContactEmailOrPhoneConfig, ContactPhoneOnlyConfig),
                ):
                    if device_info.phone_number is None:
                        raise Exception("Should never come here")
                    log_debug_message(
                        "Sending passwordless login SMS to %s", device_info.phone_number
                    )
                    sms_input = PasswordlessLoginSMSTemplateVars(
                        phone_number=device_info.phone_number,
                        user_input_code=user_input_code,
                        url_with_link_code=magic_link,
                        code_life_time=response.code_life_time,
                        pre_auth_session_id=response.pre_auth_session_id,
                        tenant_id=tenant_id,
                    )
                    await api_options.sms_delivery.ingredient_interface_impl.send_sms(
                        sms_input, user_context
                    )
                return ResendCodePostOkResult()
            return ResendCodePostRestartFlowError()

    async def consume_code_post(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodePostOkResult,
        ConsumeCodePostRestartFlowError,
        ConsumeCodePostIncorrectUserInputCodeError,
        ConsumeCodePostExpiredUserInputCodeError,
        GeneralErrorResponse,
    ]:
        response = await api_options.recipe_implementation.consume_code(
            pre_auth_session_id=pre_auth_session_id,
            user_input_code=user_input_code,
            device_id=device_id,
            link_code=link_code,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if isinstance(response, ConsumeCodeExpiredUserInputCodeError):
            return ConsumeCodePostExpiredUserInputCodeError(
                failed_code_input_attempt_count=response.failed_code_input_attempt_count,
                maximum_code_input_attempts=response.maximum_code_input_attempts,
            )
        if isinstance(response, ConsumeCodeIncorrectUserInputCodeError):
            return ConsumeCodePostIncorrectUserInputCodeError(
                failed_code_input_attempt_count=response.failed_code_input_attempt_count,
                maximum_code_input_attempts=response.maximum_code_input_attempts,
            )
        if isinstance(response, ConsumeCodeRestartFlowError):
            return ConsumeCodePostRestartFlowError()

        user = response.user

        if user.email is not None:
            ev_instance = EmailVerificationRecipe.get_instance_optional()
            if ev_instance is not None:
                token_response = await ev_instance.recipe_implementation.create_email_verification_token(
                    user.user_id, user.email, tenant_id, user_context
                )

                if isinstance(token_response, CreateEmailVerificationTokenOkResult):
                    await ev_instance.recipe_implementation.verify_email_using_token(
                        token_response.token, tenant_id, user_context
                    )

        session = await create_new_session(
            request=api_options.request,
            tenant_id=tenant_id,
            user_id=user.user_id,
            access_token_payload={},
            session_data_in_database={},
            user_context=user_context,
        )

        return ConsumeCodePostOkResult(
            created_new_user=response.created_new_user,
            user=response.user,
            session=session,
        )

    async def email_exists_get(
        self,
        email: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailExistsGetOkResult, GeneralErrorResponse]:
        response = await api_options.recipe_implementation.get_user_by_email(
            email, tenant_id, user_context
        )
        return EmailExistsGetOkResult(exists=response is not None)

    async def phone_number_exists_get(
        self,
        phone_number: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[PhoneNumberExistsGetOkResult, GeneralErrorResponse]:
        response = await api_options.recipe_implementation.get_user_by_phone_number(
            phone_number, tenant_id, user_context
        )
        return PhoneNumberExistsGetOkResult(exists=response is not None)
