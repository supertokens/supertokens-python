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

from typing import TYPE_CHECKING, Any, Dict

from httpx import AsyncClient

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo
    from .types import User
    from .interfaces import RecipeInterface, APIInterface
    from typing import Callable, Union, Awaitable

from os import environ


def default_get_email_verification_url(app_info: AppInfo) -> Callable[[User, Dict[str, Any]], Awaitable[str]]:
    async def func(_: User, __: Dict[str, Any]):
        return app_info.website_domain.get_as_string_dangerous(
        ) + app_info.website_base_path.get_as_string_dangerous() + '/verify-email'
    return func


def default_create_and_send_custom_email(app_info: AppInfo) -> Callable[[User, str, Dict[str, Any]], Awaitable[None]]:
    async def func(user: User, email_verification_url: str, _: Dict[str, Any]):
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            return
        try:
            async with AsyncClient() as client:
                await client.post('https://api.supertokens.io/0/st/auth/email/verify', json={'email': user.email, 'appName': app_info.app_name, 'emailVerifyURL': email_verification_url}, headers={'api-version': '0'})  # type: ignore
        except Exception:
            pass
    return func


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
                 apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        self.functions = functions
        self.apis = apis


class ParentRecipeEmailVerificationConfig:
    def __init__(self,
                 get_email_for_user_id: Callable[[str, Dict[str, Any]], Awaitable[str]],
                 override: Union[OverrideConfig, None] = None,
                 get_email_verification_url: Union[Callable[[
                     User, Dict[str, Any]], Awaitable[str]], None] = None,
                 create_and_send_custom_email: Union[Callable[[
                     User, str, Dict[str, Any]], Awaitable[None]], None] = None
                 ):
        self.override = override
        self.get_email_verification_url = get_email_verification_url
        self.create_and_send_custom_email = create_and_send_custom_email
        self.get_email_for_user_id = get_email_for_user_id


class EmailVerificationConfig:
    def __init__(self,
                 override: OverrideConfig,
                 get_email_verification_url: Callable[[User, Dict[str, Any]], Awaitable[str]],
                 create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]],
                 get_email_for_user_id: Callable[[str, Dict[str, Any]], Awaitable[str]]
                 ):
        self.get_email_for_user_id = get_email_for_user_id
        self.get_email_verification_url = get_email_verification_url
        self.create_and_send_custom_email = create_and_send_custom_email
        self.override = override


def validate_and_normalise_user_input(
        app_info: AppInfo, config: ParentRecipeEmailVerificationConfig):
    get_email_verification_url = config.get_email_verification_url if config.get_email_verification_url is not None \
        else default_get_email_verification_url(app_info)
    create_and_send_custom_email = config.create_and_send_custom_email if config.create_and_send_custom_email is not None \
        else default_create_and_send_custom_email(app_info)
    override = config.override
    if override is None:
        override = OverrideConfig()
    return EmailVerificationConfig(
        override=override,
        get_email_for_user_id=config.get_email_for_user_id,
        create_and_send_custom_email=create_and_send_custom_email,
        get_email_verification_url=get_email_verification_url
    )
