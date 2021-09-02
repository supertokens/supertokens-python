"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from __future__ import annotations
from httpx import AsyncClient
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo
    from .types import User
from os import environ


def default_get_email_verification_url(app_info: AppInfo):
    async def func(_: User):
        return app_info.website_domain.get_as_string_dangerous() + app_info.website_base_path.get_as_string_dangerous() + '/verify-email'
    return func


def default_create_and_send_custom_email(app_info: AppInfo):
    async def func(user: User, email_verification_url: str):
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            return
        try:
            await AsyncClient().post('https://api.supertokens.io/0/st/auth/email/verify', json={'email': user.email, 'appName': app_info.app_name, 'emailVerifyURL': email_verification_url}, headers={'api-version': '0'})
        except Exception:
            pass
    return func


async def default_handle_post_email_verification(_):
    return {}


class EmailVerificationConfig:
    def __init__(self,
                 get_email_for_user_id,
                 disable_default_implementation: bool,
                 get_email_verification_url,
                 create_and_send_custom_email,
                 handle_post_email_verification
                 ):
        self.get_email_for_user_id = get_email_for_user_id
        self.disable_default_implementation = disable_default_implementation
        self.get_email_verification_url = get_email_verification_url
        self.create_and_send_custom_email = create_and_send_custom_email
        self.handle_post_email_verification = handle_post_email_verification


def validate_and_normalise_user_input(app_info: AppInfo, config):
    disable_default_implementation = config[
        'disable_default_implementation'] if 'disable_default_implementation' in config and config[
        'disable_default_implementation'] is not None else False
    get_email_verification_url = config[
        'get_email_verification_url'] if 'get_email_verification_url' in config else default_get_email_verification_url(
        app_info)
    create_and_send_custom_email = config[
        'create_and_send_custom_email'] if 'create_and_send_custom_email' in config and config[
        'create_and_send_custom_email'] is not None else default_create_and_send_custom_email(
        app_info)
    handle_post_email_verification = config[
        'handle_post_email_verification'] if 'handle_post_email_verification' in config else default_handle_post_email_verification
    get_email_for_user_id = config['get_email_for_user_id']

    return EmailVerificationConfig(
        get_email_for_user_id,
        disable_default_implementation,
        get_email_verification_url,
        create_and_send_custom_email,
        handle_post_email_verification
    )
