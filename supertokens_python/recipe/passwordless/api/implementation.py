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

from supertokens_python.recipe.passwordless.interfaces import (
    APIInterface, APIOptions, ConsumeCodePostExpiredUserInputCodeErrorResponse,
    ConsumeCodePostIncorrectUserInputCodeErrorResponse,
    ConsumeCodePostOkResponse, ConsumeCodePostResponse,
    ConsumeCodePostRestartFlowErrorResponse,
    CreateCodePostGeneralErrorResponse, CreateCodePostOkResponse,
    CreateCodePostResponse, EmailExistsGetOkResponse, EmailExistsGetResponse,
    PhoneNumberExistsGetOkResponse, PhoneNumberExistsGetResponse,
    ResendCodePostGeneralErrorResponse, ResendCodePostOkResponse,
    ResendCodePostResponse, ResendCodePostRestartFlowErrorResponse)
from supertokens_python.recipe.passwordless.utils import (
    ContactEmailOnlyConfig, ContactEmailOrPhoneConfig, ContactPhoneOnlyConfig,
    CreateAndSendCustomEmailParameters,
    CreateAndSendCustomTextMessageParameters)
from supertokens_python.recipe.session.asyncio import create_new_session

from ..utils import PhoneOrEmailInput


class APIImplementation(APIInterface):
    async def create_code_post(self,
                               email: Union[str, None],
                               phone_number: Union[str, None],
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> CreateCodePostResponse:
        user_input_code = None
        if api_options.config.get_custom_user_input_code is not None:
            user_input_code = await api_options.config.get_custom_user_input_code(user_context)
        response = await api_options.recipe_implementation.create_code(email, phone_number, user_input_code, user_context)
        magic_link = None
        user_input_code = None
        flow_type = api_options.config.flow_type
        if flow_type in ('MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'):
            magic_link = await api_options.config.get_link_domain_and_path(PhoneOrEmailInput(phone_number=phone_number, email=email), user_context)
            magic_link += '?rid=' + api_options.recipe_id + '&preAuthSessionId=' + \
                response.pre_auth_session_id + '#' + response.link_code
        if flow_type in ('USER_INPUT_CODE', 'USER_INPUT_CODE_AND_MAGIC_LINK'):
            user_input_code = response.user_input_code

        try:
            if isinstance(api_options.config.contact_config, ContactEmailOnlyConfig) or \
                    (isinstance(api_options.config.contact_config, ContactEmailOrPhoneConfig) and email is not None):
                if email is None:
                    raise Exception("Should never come here")
                await api_options.config.contact_config.create_and_send_custom_email(CreateAndSendCustomEmailParameters(
                    email=email,
                    user_input_code=user_input_code,
                    url_with_link_code=magic_link,
                    code_life_time=response.code_life_time,
                    pre_auth_session_id=response.pre_auth_session_id
                ), user_context)
            elif isinstance(api_options.config.contact_config, (ContactEmailOrPhoneConfig, ContactPhoneOnlyConfig)):
                if phone_number is None:
                    raise Exception("Should never come here")
                await api_options.config.contact_config.create_and_send_custom_text_message(CreateAndSendCustomTextMessageParameters(
                    phone_number=phone_number,
                    user_input_code=user_input_code,
                    url_with_link_code=magic_link,
                    code_life_time=response.code_life_time,
                    pre_auth_session_id=response.pre_auth_session_id
                ), user_context)
        except Exception as e:
            return CreateCodePostGeneralErrorResponse(str(e))
        return CreateCodePostOkResponse(response.device_id, response.pre_auth_session_id, flow_type)

    async def resend_code_post(self,
                               device_id: str,
                               pre_auth_session_id: str,
                               api_options: APIOptions,
                               user_context: Dict[str, Any]) -> ResendCodePostResponse:
        device_info = await api_options.recipe_implementation.list_codes_by_device_id(
            device_id=device_id,
            user_context=user_context
        )
        if device_info is None:
            return ResendCodePostRestartFlowErrorResponse()
        if (isinstance(api_options.config.contact_config, ContactEmailOnlyConfig) and device_info.email is None) or \
                (isinstance(api_options.config.contact_config, ContactPhoneOnlyConfig) and device_info.phone_number is None):
            return ResendCodePostRestartFlowErrorResponse()
        number_of_tries_to_create_new_code = 0
        while True:
            number_of_tries_to_create_new_code += 1
            user_input_code = None
            if api_options.config.get_custom_user_input_code is not None:
                user_input_code = await api_options.config.get_custom_user_input_code(user_context)
            response = await api_options.recipe_implementation.create_new_code_for_device(
                device_id=device_id,
                user_input_code=user_input_code,
                user_context=user_context
            )
            if response.is_user_input_code_already_used_error:
                if number_of_tries_to_create_new_code >= 3:
                    return ResendCodePostGeneralErrorResponse(
                        'Failed to generate a one time code. Please try again')
                continue
            if response.is_ok:
                magic_link = None
                user_input_code = None
                flow_type = api_options.config.flow_type
                if flow_type in ('MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'):
                    if response.link_code is None or response.pre_auth_session_id is None:
                        raise Exception("Should never come here")
                    magic_link = await api_options.config.get_link_domain_and_path(PhoneOrEmailInput(device_info.phone_number, device_info.email), user_context)
                    magic_link += '?rid=' + api_options.recipe_id + '&preAuthSessionId=' + \
                        response.pre_auth_session_id + '#' + response.link_code
                if flow_type in ('USER_INPUT_CODE', 'USER_INPUT_CODE_AND_MAGIC_LINK'):
                    user_input_code = response.user_input_code

                try:
                    if isinstance(api_options.config.contact_config, ContactEmailOnlyConfig) or \
                            (isinstance(api_options.config.contact_config,
                                        ContactEmailOrPhoneConfig) and device_info.email is not None):
                        if device_info.email is None or response.code_life_time is None or response.pre_auth_session_id is None:
                            raise Exception("Should never come here")
                        await api_options.config.contact_config.create_and_send_custom_email(CreateAndSendCustomEmailParameters(
                            email=device_info.email,
                            user_input_code=user_input_code,
                            url_with_link_code=magic_link,
                            code_life_time=response.code_life_time,
                            pre_auth_session_id=response.pre_auth_session_id
                        ), user_context)
                    elif isinstance(api_options.config.contact_config, (ContactEmailOrPhoneConfig, ContactPhoneOnlyConfig)):
                        if device_info.phone_number is None or response.code_life_time is None or response.pre_auth_session_id is None:
                            raise Exception("Should never come here")
                        await api_options.config.contact_config.create_and_send_custom_text_message(CreateAndSendCustomTextMessageParameters(
                            phone_number=device_info.phone_number,
                            user_input_code=user_input_code,
                            url_with_link_code=magic_link,
                            code_life_time=response.code_life_time,
                            pre_auth_session_id=response.pre_auth_session_id
                        ), user_context)
                except Exception as e:
                    return ResendCodePostGeneralErrorResponse(str(e))
            return ResendCodePostOkResponse()

    async def consume_code_post(self,
                                pre_auth_session_id: str,
                                user_input_code: Union[str, None],
                                device_id: Union[str, None],
                                link_code: Union[str, None],
                                api_options: APIOptions,
                                user_context: Dict[str, Any]) -> ConsumeCodePostResponse:
        response = await api_options.recipe_implementation.consume_code(
            pre_auth_session_id=pre_auth_session_id,
            user_input_code=user_input_code,
            device_id=device_id,
            link_code=link_code,
            user_context=user_context
        )
        if response.is_expired_user_input_code_error:
            if response.failed_code_input_attempt_count is None or response.maximum_code_input_attempts is None:
                raise Exception("Should never come here")
            return ConsumeCodePostExpiredUserInputCodeErrorResponse(
                failed_code_input_attempt_count=response.failed_code_input_attempt_count,
                maximum_code_input_attempts=response.maximum_code_input_attempts
            )
        if response.is_incorrect_user_input_code_error:
            if response.failed_code_input_attempt_count is None or response.maximum_code_input_attempts is None:
                raise Exception("Should never come here")
            return ConsumeCodePostIncorrectUserInputCodeErrorResponse(
                failed_code_input_attempt_count=response.failed_code_input_attempt_count,
                maximum_code_input_attempts=response.maximum_code_input_attempts
            )
        if response.is_restart_flow_error:
            return ConsumeCodePostRestartFlowErrorResponse()
        if response.user is None or response.created_new_user is None:
            raise Exception("Should never come here")
        user = response.user
        session = await create_new_session(api_options.request, user.user_id, {}, {}, user_context=user_context)
        return ConsumeCodePostOkResponse(
            created_new_user=response.created_new_user,
            user=response.user,
            session=session
        )

    async def email_exists_get(self, email: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        response = await api_options.recipe_implementation.get_user_by_email(email, user_context)
        return EmailExistsGetOkResponse(exists=response is not None)

    async def phone_number_exists_get(self, phone_number: str, api_options: APIOptions, user_context: Dict[str, Any]) -> PhoneNumberExistsGetResponse:
        response = await api_options.recipe_implementation.get_user_by_phone_number(phone_number, user_context)
        return PhoneNumberExistsGetOkResponse(exists=response is not None)
