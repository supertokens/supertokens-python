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
from typing import Union

from supertokens_python.recipe.passwordless.interfaces import APIInterface, APIOptions, PhoneNumberExistsGetResponse, \
    EmailExistsGetResponse, ConsumeCodePostResponse, ResendCodePostResponse, CreateCodePostResponse, \
    CreateCodePostGeneralErrorResponse, CreateCodePostOkResponse, EmailExistsGetOkResponse, \
    PhoneNumberExistsGetOkResponse, ResendCodePostOkResponse, ResendCodePostRestartFlowErrorResponse, \
    ResendCodePostGeneralErrorResponse, ConsumeCodePostOkResponse, \
    ConsumeCodePostExpiredUserInputCodeErrorResponse, ConsumeCodePostIncorrectUserInputCodeErrorResponse, \
    ConsumeCodePostRestartFlowErrorResponse
from supertokens_python.recipe.passwordless.utils import ContactPhoneOnlyConfig, ContactEmailOnlyConfig, \
    ContactEmailOrPhoneConfig, CreateAndSendCustomTextMessageParameters, CreateAndSendCustomEmailParameters
from supertokens_python.recipe.session.asyncio import create_new_session


class APIImplementation(APIInterface):
    async def create_code_post(self, email: Union[str, None], phone_number: Union[str, None],
                               api_options: APIOptions) -> CreateCodePostResponse:
        user_input_code = None
        if api_options.config.get_custom_user_input_code is not None:
            user_input_code = await api_options.config.get_custom_user_input_code()
        response = await api_options.recipe_implementation.create_code(email, phone_number, user_input_code)
        magic_link = None
        user_input_code = None
        flow_type = api_options.config.flow_type
        if flow_type == 'MAGIC_LINK' or flow_type == 'USER_INPUT_CODE_AND_MAGIC_LINK':
            code = email if email is not None else phone_number
            magic_link = await api_options.config.get_link_domain_and_path(code)
            magic_link += '?rid=' + api_options.recipe_id + '&preAuthSessionId=' + response.pre_auth_session_id + '#' + response.link_code
        if flow_type == 'USER_INPUT_CODE' or flow_type == 'USER_INPUT_CODE_AND_MAGIC_LINK':
            user_input_code = response.user_input_code

        try:
            if isinstance(api_options.config.contact_config, ContactEmailOnlyConfig) or \
                    (isinstance(api_options.config.contact_config, ContactEmailOrPhoneConfig) and email is not None):
                await api_options.config.contact_config.create_and_send_custom_email(CreateAndSendCustomEmailParameters(
                    email=email,
                    user_input_code=user_input_code,
                    url_with_link_code=magic_link,
                    code_life_time=response.code_life_time,
                    pre_auth_session_id=response.pre_auth_session_id
                ))
            elif isinstance(api_options.config.contact_config, ContactEmailOrPhoneConfig) or \
                    isinstance(api_options.config.contact_config, ContactPhoneOnlyConfig):
                await api_options.config.contact_config.create_and_send_custom_text_message(CreateAndSendCustomTextMessageParameters(
                    phone_number=phone_number,
                    user_input_code=user_input_code,
                    url_with_link_code=magic_link,
                    code_life_time=response.code_life_time,
                    pre_auth_session_id=response.pre_auth_session_id
                ))
        except Exception as e:
            return CreateCodePostGeneralErrorResponse(str(e))
        return CreateCodePostOkResponse(response.device_id, response.pre_auth_session_id, flow_type)

    async def resend_code_post(self, device_id: str, pre_auth_session_id: str,
                               api_options: APIOptions) -> ResendCodePostResponse:
        device_info = await api_options.recipe_implementation.list_codes_by_device_id(
            device_id=device_id
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
                user_input_code = await api_options.config.get_custom_user_input_code()
            response = await api_options.recipe_implementation.create_new_code_for_device(
                device_id=device_id,
                user_input_code=user_input_code
            )
            if response.is_user_input_code_already_used_error:
                if number_of_tries_to_create_new_code >= 3:
                    return ResendCodePostGeneralErrorResponse('Failed to generate a one time code. Please try again')
                continue
            if response.is_ok:
                magic_link = None
                user_input_code = None
                flow_type = api_options.config.flow_type
                if flow_type == 'MAGIC_LINK' or flow_type == 'USER_INPUT_CODE_AND_MAGIC_LINK':
                    code = device_info.email if device_info.email is not None else device_info.phone_number
                    magic_link = await api_options.config.get_link_domain_and_path(code)
                    magic_link += '?rid=' + api_options.recipe_id + '&preAuthSessionId=' + response.pre_auth_session_id + '#' + response.link_code
                if flow_type == 'USER_INPUT_CODE' or flow_type == 'USER_INPUT_CODE_AND_MAGIC_LINK':
                    user_input_code = response.user_input_code

                try:
                    if isinstance(api_options.config.contact_config, ContactEmailOnlyConfig) or \
                            (isinstance(api_options.config.contact_config,
                                        ContactEmailOrPhoneConfig) and device_info.email is not None):
                        await api_options.config.contact_config.create_and_send_custom_email(CreateAndSendCustomEmailParameters(
                            email=device_info.email,
                            user_input_code=user_input_code,
                            url_with_link_code=magic_link,
                            code_life_time=response.code_life_time,
                            pre_auth_session_id=response.pre_auth_session_id
                        ))
                    elif isinstance(api_options.config.contact_config, ContactEmailOrPhoneConfig) or \
                            isinstance(api_options.config.contact_config, ContactPhoneOnlyConfig):
                        await api_options.config.contact_config.create_and_send_custom_text_message(CreateAndSendCustomTextMessageParameters(
                            phone_number=device_info.phone_number,
                            user_input_code=user_input_code,
                            url_with_link_code=magic_link,
                            code_life_time=response.code_life_time,
                            pre_auth_session_id=response.pre_auth_session_id
                        ))
                except Exception as e:
                    return ResendCodePostGeneralErrorResponse(str(e))
            return ResendCodePostOkResponse()

    async def consume_code_post(self, pre_auth_session_id: str, user_input_code: Union[str, None],
                                device_id: Union[str, None], link_code: Union[str, None],
                                api_options: APIOptions) -> ConsumeCodePostResponse:
        response = await api_options.recipe_implementation.consume_code(
            pre_auth_session_id=pre_auth_session_id,
            user_input_code=user_input_code,
            device_id=device_id,
            link_code=link_code
        )
        if response.is_expired_user_input_code_error:
            return ConsumeCodePostExpiredUserInputCodeErrorResponse(
                failed_code_input_attempt_count=response.failed_code_input_attempt_count,
                maximum_code_input_attempts=response.maximum_code_input_attempts
            )
        elif response.is_incorrect_user_input_code_error:
            return ConsumeCodePostIncorrectUserInputCodeErrorResponse(
                failed_code_input_attempt_count=response.failed_code_input_attempt_count,
                maximum_code_input_attempts=response.maximum_code_input_attempts
            )
        elif response.is_restart_flow_error:
            return ConsumeCodePostRestartFlowErrorResponse()
        user = response.user
        session = await create_new_session(api_options.request, user.user_id, {}, {})
        return ConsumeCodePostOkResponse(
            created_new_user=response.created_new_user,
            user=response.user,
            session=session
        )

    async def email_exists_get(self, email: str, api_options: APIOptions) -> EmailExistsGetResponse:
        response = await api_options.recipe_implementation.get_user_by_email(email)
        return EmailExistsGetOkResponse(exists=response is not None)

    async def phone_number_exists_get(self, phone_number: str, api_options: APIOptions) -> PhoneNumberExistsGetResponse:
        response = await api_options.recipe_implementation.get_user_by_phone_number(phone_number)
        return PhoneNumberExistsGetOkResponse(exists=response is not None)
