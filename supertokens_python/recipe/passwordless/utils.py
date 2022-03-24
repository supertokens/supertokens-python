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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Union

from typing_extensions import Literal

if TYPE_CHECKING:
    from .interfaces import RecipeInterface, APIInterface
    from supertokens_python import AppInfo

from re import fullmatch

from phonenumbers import is_valid_number, parse  # type: ignore


async def default_validate_phone_number(value: str):
    try:
        parsed_phone_number: Any = parse(value, None)
        if not is_valid_number(parsed_phone_number):
            return 'Phone number is invalid'
    except Exception:
        return 'Phone number is invalid'


def default_get_link_domain_and_path(app_info: AppInfo):
    async def get_link_domain_and_path(_: PhoneOrEmailInput, __: Dict[str, Any]) -> str:
        return app_info.website_domain.get_as_string_dangerous(
        ) + app_info.website_base_path.get_as_string_dangerous() + '/verify'
    return get_link_domain_and_path


async def default_validate_email(value: str):
    pattern = r"^(([^<>()\[\]\\.,;:\s@\"]+(\.[^<>()\[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"
    if fullmatch(pattern, value) is None:
        return 'Email is invalid'


async def default_create_and_send_custom_text_message(
    _: CreateAndSendCustomTextMessageParameters,
    __: Dict[str, Any]
) -> None:
    # TODO
    pass


async def default_create_and_send_custom_email(
    _: CreateAndSendCustomEmailParameters,
    __: Dict[str, Any]
) -> None:
    # TODO
    pass


class CreateAndSendCustomEmailParameters:
    def __init__(self,
                 code_life_time: int,
                 pre_auth_session_id: str,
                 email: str,
                 user_input_code: Union[str, None] = None,
                 url_with_link_code: Union[str, None] = None):
        self.email: str = email
        self.code_life_time: int = code_life_time
        self.pre_auth_session_id: str = pre_auth_session_id
        self.user_input_code: Union[str, None] = user_input_code
        self.url_with_link_code: Union[str, None] = url_with_link_code


class CreateAndSendCustomTextMessageParameters:
    def __init__(self,
                 code_life_time: int,
                 pre_auth_session_id: str,
                 phone_number: str,
                 user_input_code: Union[str, None] = None,
                 url_with_link_code: Union[str, None] = None):
        self.phone_number: str = phone_number
        self.code_life_time: int = code_life_time
        self.pre_auth_session_id: str = pre_auth_session_id
        self.user_input_code: Union[str, None] = user_input_code
        self.url_with_link_code: Union[str, None] = url_with_link_code


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface],
                                        None] = None, apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        self.functions = functions
        self.apis = apis


class ContactConfig(ABC):
    def __init__(
            self, contact_method: Literal['PHONE', 'EMAIL', 'EMAIL_OR_PHONE']):
        self.contact_method = contact_method


class ContactPhoneOnlyConfig(ContactConfig):
    def __init__(self,
                 create_and_send_custom_text_message: Callable[
                     [CreateAndSendCustomTextMessageParameters, Dict[str, Any]], Awaitable[None]],
                 validate_phone_number: Union[Callable[[
                     str], Awaitable[Union[str, None]]], None] = None,
                 ):
        super().__init__('PHONE')
        if create_and_send_custom_text_message is None:
            self.create_and_send_custom_text_message = default_create_and_send_custom_text_message
        else:
            self.create_and_send_custom_text_message = create_and_send_custom_text_message
        if validate_phone_number is None:
            self.validate_phone_number = default_validate_phone_number
        else:
            self.validate_phone_number = validate_phone_number


class ContactEmailOnlyConfig(ContactConfig):
    def __init__(self,
                 create_and_send_custom_email: Callable[
                     [CreateAndSendCustomEmailParameters, Dict[str, Any]], Awaitable[None]],
                 validate_email_address: Union[Callable[[
                     str], Awaitable[Union[str, None]]], None] = None
                 ):
        super().__init__('EMAIL')
        if create_and_send_custom_email is None:
            self.create_and_send_custom_email = default_create_and_send_custom_email
        else:
            self.create_and_send_custom_email = create_and_send_custom_email
        if validate_email_address is None:
            self.validate_email_address = default_validate_email
        else:
            self.validate_email_address = validate_email_address


class ContactEmailOrPhoneConfig(ContactConfig):
    def __init__(self,
                 create_and_send_custom_email: Callable[
                     [CreateAndSendCustomEmailParameters, Dict[str, Any]], Awaitable[None]],
                 create_and_send_custom_text_message: Callable[
                     [CreateAndSendCustomTextMessageParameters, Dict[str, Any]], Awaitable[None]],
                 validate_email_address: Union[Callable[[
                     str], Awaitable[Union[str, None]]], None] = None,
                 validate_phone_number: Union[Callable[[
                     str], Awaitable[Union[str, None]]], None] = None,
                 ):
        super().__init__('EMAIL_OR_PHONE')
        if create_and_send_custom_email is None:
            self.create_and_send_custom_email = default_create_and_send_custom_email
        else:
            self.create_and_send_custom_email = create_and_send_custom_email
        if validate_email_address is None:
            self.validate_email_address = default_validate_email
        else:
            self.validate_email_address = validate_email_address
        if create_and_send_custom_text_message is None:
            self.create_and_send_custom_text_message = default_create_and_send_custom_text_message
        else:
            self.create_and_send_custom_text_message = create_and_send_custom_text_message
        if validate_phone_number is None:
            self.validate_phone_number = default_validate_phone_number
        else:
            self.validate_phone_number = validate_phone_number


class PhoneOrEmailInput:
    def __init__(self, phone_number: Union[str, None], email: Union[str, None]):
        self.phone_number = phone_number
        self.email = email


class PasswordlessConfig:
    def __init__(self,
                 contact_config: ContactConfig,
                 override: OverrideConfig,
                 flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
                 get_link_domain_and_path: Callable[[PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]],
                 get_custom_user_input_code: Union[Callable[[
                     Dict[str, Any]], Awaitable[str]], None] = None
                 ):
        self.contact_config = contact_config
        self.override = override
        self.flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'] = flow_type
        self.get_custom_user_input_code = get_custom_user_input_code
        self.get_link_domain_and_path = get_link_domain_and_path


def validate_and_normalise_user_input(
        app_info: AppInfo,
        contact_config: ContactConfig,
        flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
        override: Union[OverrideConfig, None] = None,
        get_link_domain_and_path: Union[Callable[[
            PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None] = None,
        get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = None):

    if override is None:
        override = OverrideConfig()

    if get_link_domain_and_path is None:
        get_link_domain_and_path = default_get_link_domain_and_path(app_info)

    return PasswordlessConfig(
        contact_config=contact_config,
        override=OverrideConfig(
            functions=override.functions,
            apis=override.apis),
        flow_type=flow_type,
        get_link_domain_and_path=get_link_domain_and_path,
        get_custom_user_input_code=get_custom_user_input_code
    )
