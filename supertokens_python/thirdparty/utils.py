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
from .types import User, INPUT_SCHEMA
from typing import List, Literal, Callable, Awaitable, TYPE_CHECKING
if TYPE_CHECKING:
    from .recipe import ThirdPartyRecipe
    from .provider import Provider
from supertokens_python.utils import validate_the_structure_of_user_input
from .exceptions import (
    raise_unknown_user_id_exception
)
from supertokens_python.exceptions import raise_bad_input_exception


async def default_handle_post_sign_up_in(_: User, __: any, ___: bool):
    pass


async def default_set_session_data_for_session(_: User, __: any, ___: Literal['signin', 'signup']):
    return {}


async def default_set_jwt_payload_for_session(_: User, __: any, ___: Literal['signin', 'signup']):
    return {}


class SessionFeature:
    def __init__(self, set_jwt_payload: Callable[[User, any, Literal['signin', 'signup']], Awaitable[any]],
                 set_session_data: Callable[[User, any, Literal['signin', 'signup']], Awaitable[any]]):
        self.set_jwt_payload = set_jwt_payload
        self.set_session_data = set_session_data


def validate_and_normalise_session_feature_config(config=None) -> SessionFeature:
    set_jwt_payload = config[
        'set_jwt_payload'] if config is not None and 'set_jwt_payload' in config else default_set_jwt_payload_for_session
    set_session_data = config[
        'set_session_data'] if config is not None and 'set_session_data' in config else default_set_session_data_for_session

    return SessionFeature(set_jwt_payload, set_session_data)


class SignInAndUpFeature:
    def __init__(self, disable_default_implementation: bool, handle_post_sign_up_in: Callable[[User, any, bool], Awaitable], providers: List[Provider]):
        self.disable_default_implementation = disable_default_implementation
        self.handle_post_sign_up_in = handle_post_sign_up_in
        self.providers = providers


def validate_and_normalise_sign_in_and_up_config(recipe: ThirdPartyRecipe, config=None) -> SignInAndUpFeature:
    if config is None:
        config = {}
    disable_default_implementation = False
    if 'disable_default_implementation' in config:
        disable_default_implementation = config['disable_default_implementation']
    handle_post_sign_up_in = config[
        'handle_post_sign_in'] if 'handle_post_sign_in' in config else default_handle_post_sign_up_in
    if 'providers' not in config or not isinstance(config['providers'], list) or len(config['providers']) == 0:
        raise_bad_input_exception(recipe, 'thirdparty recipe requires atleast 1 provider to be passed in '
                                          'signInAndUpFeature.providers config')
    providers = config['providers']
    return SignInAndUpFeature(disable_default_implementation, handle_post_sign_up_in, providers)


class SignOutFeature:
    def __init__(self, disable_default_implementation: bool):
        self.disable_default_implementation = disable_default_implementation


def validate_and_normalise_sign_out_config(config=None) -> SignOutFeature:
    if config is None:
        config = {}
    disable_default_implementation = False
    if 'disable_default_implementation' in config:
        disable_default_implementation = config['disable_default_implementation']
    return SignOutFeature(disable_default_implementation)


def email_verification_create_and_send_custom_email(recipe: ThirdPartyRecipe, create_and_send_custom_email):
    async def func(user, link):
        user_info = await recipe.get_user_by_id(user.id)
        if user_info is None:
            raise_unknown_user_id_exception(recipe, 'User ID unknown')
        return await create_and_send_custom_email(user_info, link)

    return func


def email_verification_get_email_verification_url(recipe: ThirdPartyRecipe, get_email_verification_url):
    async def func(user):
        user_info = await recipe.get_user_by_id(user.id)
        if user_info is None:
            raise_unknown_user_id_exception(recipe, 'User ID unknown')
        return await get_email_verification_url(user_info)

    return func


def email_verification_handle_post_email_verification(recipe: ThirdPartyRecipe, handle_post_email_verification):
    async def func(user):
        user_info = await recipe.get_user_by_id(user.id)
        if user_info is None:
            raise_unknown_user_id_exception(recipe, 'User ID unknown')
        return await handle_post_email_verification(user_info)

    return func


def validate_and_normalise_email_verification_config(recipe: ThirdPartyRecipe, config=None):
    if config is None:
        return {
            'get_email_for_user_id': recipe.get_email_for_user_id
        }
    create_and_send_custom_email = None
    get_email_verification_url = None
    handle_post_email_verification = None
    if 'create_and_send_custom_email' in config:
        create_and_send_custom_email = email_verification_create_and_send_custom_email(recipe, config[
            'create_and_send_custom_email'])
    if 'get_email_verification_url' in config:
        get_email_verification_url = email_verification_get_email_verification_url(recipe,
                                                                                   config['get_email_verification_url'])
    if 'handle_post_email_verification' in config:
        handle_post_email_verification = email_verification_handle_post_email_verification(recipe, config[
            'handle_post_email_verification'])

    return {
        'disable_default_implementation': config[
            'disable_default_implementation'] if 'disable_default_implementation' in config else None,
        'get_email_for_user_id': recipe.get_email_for_user_id,
        'create_and_send_custom_email': create_and_send_custom_email,
        'get_email_verification_url': get_email_verification_url,
        'handle_post_email_verification': handle_post_email_verification
    }


class ThirdPartyConfig:
    def __init__(self,
                 session_feature: SessionFeature,
                 sign_in_and_up_feature: SignInAndUpFeature,
                 sign_out_feature: SignOutFeature,
                 email_verification_feature: any):
        self.session_feature = session_feature
        self.sign_in_and_up_feature = sign_in_and_up_feature
        self.sign_out_feature = sign_out_feature
        self.email_verification_feature = email_verification_feature


def validate_and_normalise_user_input(recipe: ThirdPartyRecipe, config) -> ThirdPartyConfig:
    validate_the_structure_of_user_input(config, INPUT_SCHEMA, 'thirdparty recipe', recipe)
    session_feature = validate_and_normalise_session_feature_config(
        config['session_feature'] if 'session_feature' in config else None)
    sign_in_and_up_feature = validate_and_normalise_sign_in_and_up_config(
        recipe,
        config['sign_in_and_up_feature'] if 'sign_in_and_up_feature' in config else None)
    sign_out_feature = validate_and_normalise_sign_out_config(
        config['sign_out_feature'] if 'sign_out_feature' in config else None)
    email_verification_feature = validate_and_normalise_email_verification_config(
        recipe,
        config['email_verification_feature'] if 'email_verification_feature' in config else None)
    return ThirdPartyConfig(session_feature, sign_in_and_up_feature, sign_out_feature, email_verification_feature)
