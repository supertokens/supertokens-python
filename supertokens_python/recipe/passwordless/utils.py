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

from abc import ABC
from typing import TYPE_CHECKING, Callable, Union, Awaitable, Literal

if TYPE_CHECKING:
    from .interfaces import RecipeInterface, APIInterface
    from supertokens_python import AppInfo
from phonenumbers import parse, is_valid_number
from re import fullmatch


async def default_validate_phone_number(value: str):
    try:
        parsed_phone_number = parse(value, None)
        if not is_valid_number(parsed_phone_number):
            return 'Phone number is invalid'
    except Exception:
        return 'Phone number is invalid'


def default_get_link_domain_and_path(app_info: AppInfo):
    async def get_link_domain_and_path(_: str):
        return app_info.website_domain.get_as_string_dangerous() + app_info.website_base_path.get_as_string_dangerous() + '/verify'
    return get_link_domain_and_path


async def default_validate_email(value: str):
    pattern = r"^(([^<>()\[\]\\.,;:\s@\"]+(\.[^<>()\[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"
    if fullmatch(pattern, value) is None:
        return 'Email is invalid'


async def default_create_and_send_custom_text_message(
    params: CreateAndSendCustomEmailParameters
):
    # TODO
    pass


async def default_create_and_send_custom_email(
    param: CreateAndSendCustomTextMessageParameters
):
    # TODO
    pass


class CreateAndSendCustomEmailParameters:
    def __init__(self,
                 code_life_time: int,
                 pre_auth_session_id: str,
                 email: str,
                 user_input_code: Union[str, None] = None,
                 url_with_link_code: Union[str, None] = None):
        self.email = email
        self.code_life_time = code_life_time
        self.pre_auth_session_id = pre_auth_session_id
        self.user_input_code = user_input_code
        self.url_with_link_code = url_with_link_code


class CreateAndSendCustomTextMessageParameters:
    def __init__(self,
                 code_life_time: int,
                 pre_auth_session_id: str,
                 phone_number: str,
                 user_input_code: Union[str, None] = None,
                 url_with_link_code: Union[str, None] = None):
        self.phone_number = phone_number
        self.code_life_time = code_life_time
        self.pre_auth_session_id = pre_auth_session_id
        self.user_input_code = user_input_code
        self.url_with_link_code = url_with_link_code


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface],
                                        None] = None, apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        self.functions = functions
        self.apis = apis


class ContactConfig(ABC):
    def __init__(self, contact_method: Literal['PHONE', 'EMAIL', 'EMAIL_OR_PHONE']):
        self.contact_method = contact_method


class ContactPhoneOnlyConfig(ContactConfig):
    def __init__(self,
                 create_and_send_custom_text_message: Callable[
                     [CreateAndSendCustomTextMessageParameters], Awaitable[None]],
                 validate_phone_number: Union[Callable[[str], Awaitable[Union[str, None]]], None] = None,
                 ):
        super().__init__('PHONE')
        self.validate_phone_number = validate_phone_number
        self.create_and_send_custom_text_message = create_and_send_custom_text_message


class ContactEmailOnlyConfig(ContactConfig):
    def __init__(self,
                 create_and_send_custom_email: Callable[
                     [CreateAndSendCustomEmailParameters], Awaitable[None]],
                 validate_email_address: Union[Callable[[str], Awaitable[Union[str, None]]], None] = None
                 ):
        super().__init__('EMAIL')
        self.validate_email_address = validate_email_address
        self.create_and_send_custom_email = create_and_send_custom_email


class ContactEmailOrPhoneConfig(ContactConfig):
    def __init__(self,
                 create_and_send_custom_email: Callable[
                     [CreateAndSendCustomEmailParameters], Awaitable[None]],
                 create_and_send_custom_text_message: Callable[
                     [CreateAndSendCustomTextMessageParameters], Awaitable[None]],
                 validate_email_address: Union[Callable[[str], Awaitable[Union[str, None]]], None] = None,
                 validate_phone_number: Union[Callable[[str], Awaitable[Union[str, None]]], None] = None,
                 ):
        super().__init__('EMAIL_OR_PHONE')
        self.validate_email_address = validate_email_address
        self.create_and_send_custom_email = create_and_send_custom_email
        self.validate_phone_number = validate_phone_number
        self.create_and_send_custom_text_message = create_and_send_custom_text_message


class PasswordlessConfig:
    def __init__(self,
                 contact_config: ContactConfig,
                 override: OverrideConfig,
                 flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
                 get_link_domain_and_path: Callable[[str], Awaitable[Union[str, None]]],
                 get_custom_user_input_code: Union[Callable[[], Awaitable[str]], None] = None
                 ):
        self.contact_config = contact_config
        self.override = override
        self.flow_type = flow_type
        self.get_custom_user_input_code = get_custom_user_input_code
        self.get_link_domain_and_path = get_link_domain_and_path


def validate_and_normalise_user_input(
        app_info: AppInfo,
        contact_config: ContactConfig,
        flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
        override: Union[OverrideConfig, None] = None,
        get_link_domain_and_path: Union[Callable[[str], Awaitable[Union[str, None]]]] = None,
        get_custom_user_input_code: Union[Callable[[], Awaitable[str]], None] = None):

    if override is None:
        override = OverrideConfig()

    if get_link_domain_and_path is None:
        get_link_domain_and_path = default_get_link_domain_and_path(app_info)

    if isinstance(contact_config, ContactEmailOnlyConfig):
        if contact_config.create_and_send_custom_email is None:
            contact_config.create_and_send_custom_email = default_create_and_send_custom_email
        if contact_config.validate_email_address is None:
            contact_config.validate_email_address = default_validate_email
    elif isinstance(contact_config, ContactPhoneOnlyConfig):
        if contact_config.create_and_send_custom_text_message is None:
            contact_config.create_and_send_custom_text_message = default_create_and_send_custom_text_message
        if contact_config.validate_phone_number is None:
            contact_config.validate_phone_number = default_validate_phone_number
    else:
        if contact_config.create_and_send_custom_text_message is None:
            contact_config.create_and_send_custom_text_message = default_create_and_send_custom_text_message
        if contact_config.validate_phone_number is None:
            contact_config.validate_phone_number = default_validate_phone_number
        if contact_config.create_and_send_custom_email is None:
            contact_config.create_and_send_custom_email = default_create_and_send_custom_email
        if contact_config.validate_email_address is None:
            contact_config.validate_email_address = default_validate_email

    if get_link_domain_and_path is not None:
        get_link_domain_and_path = default_get_link_domain_and_path(app_info)
    return PasswordlessConfig(
        contact_config=contact_config,
        override=OverrideConfig(functions=override.functions, apis=override.apis),
        flow_type=flow_type,
        get_link_domain_and_path=get_link_domain_and_path,
        get_custom_user_input_code=get_custom_user_input_code
    )
