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

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.passwordless.interfaces import APIInterface, APIOptions, CreateCodePostGeneralErrorResponse
from supertokens_python.recipe.passwordless.utils import ContactPhoneOnlyConfig, ContactEmailOnlyConfig, \
    ContactEmailOrPhoneConfig
from phonenumbers import parse, format_number
import phonenumbers


async def create_code(api_implementation: APIInterface, api_options: APIOptions):
    if api_implementation.disable_create_code_post:
        return None

    body = await api_options.request.json()

    email: Union[str, None] = None
    phone_number: Union[str, None] = None

    if ('email' in body and 'phoneNumber' in body) or ('email' not in body and 'phoneNumber' not in body):
        raise_bad_input_exception('Please provide exactly one of email or phoneNumber')

    if 'email' not in body and isinstance(api_options.config.contact_config, ContactEmailOnlyConfig):
        raise_bad_input_exception('Please provide an email since you have set the contactMethod to "EMAIL"')

    if 'phoneNumber' not in body and isinstance(api_options.config.contact_config, ContactPhoneOnlyConfig):
        raise_bad_input_exception('Please provide a phoneNumber since you have set the contactMethod to "PHONE"')

    if 'email' in body:
        email = body['email']
    if 'phoneNumber' in body:
        phone_number = body['phoneNumber']

    if email is not None and (
        isinstance(api_options.config.contact_config, ContactEmailOnlyConfig)
        or
        isinstance(api_options.config.contact_config, ContactEmailOrPhoneConfig)
    ):
        email = email.strip()
        validation_error = await api_options.config.contact_config.validate_email_address(email)
        if validation_error is not None:
            api_options.response.set_json_content(CreateCodePostGeneralErrorResponse(validation_error).to_json())
            return api_options.response

    if phone_number is not None and (
        isinstance(api_options.config.contact_config, ContactPhoneOnlyConfig)
        or
        isinstance(api_options.config.contact_config, ContactEmailOrPhoneConfig)
    ):
        validation_error = await api_options.config.contact_config.validate_phone_number(phone_number)
        if validation_error is not None:
            api_options.response.set_json_content(CreateCodePostGeneralErrorResponse(validation_error).to_json())
            return api_options.response
        try:
            validated_phone_number = parse(phone_number, None)
            phone_number = format_number(validated_phone_number, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            phone_number = phone_number.strip()
    result = await api_implementation.create_code_post(
        email=email, phone_number=phone_number, api_options=api_options)
    api_options.response.set_json_content(result.to_json())

    return api_options.response
