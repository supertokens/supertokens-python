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
from .types import (
    User,
    INPUT_SCHEMA,
    ThirdPartyContext,
    NextPaginationToken,
    EmailPasswordSignInContext,
    EmailPasswordSignUpContext,
    EmailPasswordSessionDataAndJWTContext
)
from typing import List, Literal, Callable, Awaitable, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from .recipe import ThirdPartyEmailPasswordRecipe
from supertokens_python.utils import validate_the_structure_of_user_input
from .exceptions import (
    raise_unknown_user_id_exception,
    raise_invalid_pagination_token_exception
)
from base64 import b64encode, b64decode
from supertokens_python.emailpassword.types import UsersResponse, User as EmailPasswordUser
from supertokens_python.thirdparty.types import User as ThirdPartyPasswordUser


async def default_handle_post_sign_up(_: User, __: Union[EmailPasswordSignUpContext, ThirdPartyContext]):
    pass


async def default_handle_post_sign_in(_: User, __: Union[EmailPasswordSignInContext, ThirdPartyContext]):
    pass


async def default_set_session_data_for_session(_: User,
                                               __: Union[EmailPasswordSessionDataAndJWTContext, ThirdPartyContext],
                                               ___: Literal['signin', 'signup']):
    return {}


async def default_set_jwt_payload_for_session(_: User,
                                              __: Union[EmailPasswordSessionDataAndJWTContext, ThirdPartyContext],
                                              ___: Literal['signin', 'signup']):
    return {}


class SessionFeature:
    def __init__(self, set_jwt_payload: Callable[
        [User, Union[EmailPasswordSessionDataAndJWTContext, ThirdPartyContext], Literal['signin', 'signup']], Awaitable[
            any]],
        set_session_data: Callable[[User, Union[EmailPasswordSessionDataAndJWTContext, ThirdPartyContext],
                                    Literal['signin', 'signup']], Awaitable[any]]):
        self.set_jwt_payload = set_jwt_payload
        self.set_session_data = set_session_data


def validate_and_normalise_session_feature_config(config=None) -> SessionFeature:
    intermediate_set_jwt_payload = config[
        'set_jwt_payload'] if config is not None and 'set_jwt_payload' in config else default_set_jwt_payload_for_session

    async def set_jwt_payload(user: Union[EmailPasswordUser, ThirdPartyPasswordUser],
                              context: Union[EmailPasswordSessionDataAndJWTContext, ThirdPartyContext],
                              action: Literal['signin', 'signup']):
        if isinstance(user, EmailPasswordUser):
            return await intermediate_set_jwt_payload(User(user.user_id, user.email, user.time_joined, None),
                                                      context, action)
        return await intermediate_set_jwt_payload(user, context, action)

    intermediate_set_session_data = config[
        'set_session_data'] if config is not None and 'set_session_data' in config else default_set_session_data_for_session

    async def set_session_data(user: Union[EmailPasswordUser, ThirdPartyPasswordUser],
                               context: Union[EmailPasswordSessionDataAndJWTContext, ThirdPartyContext],
                               action: Literal['signin', 'signup']):
        if isinstance(user, EmailPasswordUser):
            return await intermediate_set_session_data(User(user.user_id, user.email, user.time_joined, None),
                                                       context, action)
        return await intermediate_set_session_data(user, context, action)

    return SessionFeature(set_jwt_payload, set_session_data)


class SignUpFeature:
    def __init__(self, disable_default_implementation: bool, form_fields: List,
                 handle_post_sign_up: Callable[
                     [User, Union[EmailPasswordSignUpContext, ThirdPartyContext]], Awaitable]):
        self.disable_default_implementation = disable_default_implementation
        self.form_fields = form_fields
        self.handle_post_sign_up = handle_post_sign_up


def validate_and_normalise_sign_up_config(config=None) -> SignUpFeature:
    if config is None:
        config = {}
    disable_default_implementation = False
    if 'disable_default_implementation' in config:
        disable_default_implementation = config['disable_default_implementation']
    form_fields = config['form_fields'] if 'form_fields' in config else []
    intermediate_handle_post_sign_up = config[
        'handle_post_sign_up'] if 'handle_post_sign_up' in config else default_handle_post_sign_up

    async def handle_post_sign_up(user: Union[EmailPasswordUser, ThirdPartyPasswordUser],
                                  context: Union[EmailPasswordSignUpContext, ThirdPartyContext]):
        if isinstance(user, EmailPasswordUser):
            return await intermediate_handle_post_sign_up(User(user.user_id, user.email, user.time_joined, None),
                                                          context)
        return await intermediate_handle_post_sign_up(user, context)

    return SignUpFeature(disable_default_implementation, form_fields, handle_post_sign_up)


class SignInFeature:
    def __init__(self, disable_default_implementation: bool, handle_post_sign_in: Callable[
            [User, Union[EmailPasswordSignInContext, ThirdPartyContext]], Awaitable]):
        self.disable_default_implementation = disable_default_implementation
        self.handle_post_sign_in = handle_post_sign_in


def validate_and_normalise_sign_in_config(config=None) -> SignInFeature:
    if config is None:
        config = {}
    disable_default_implementation = False
    if 'disable_default_implementation' in config:
        disable_default_implementation = config['disable_default_implementation']
    intermediate_handle_post_sign_in = config[
        'handle_post_sign_in'] if 'handle_post_sign_in' in config else default_handle_post_sign_in

    async def handle_post_sign_in(user: Union[EmailPasswordUser, ThirdPartyPasswordUser],
                                  context: Union[EmailPasswordSignInContext, ThirdPartyContext]):
        if isinstance(user, EmailPasswordUser):
            return await intermediate_handle_post_sign_in(User(user.user_id, user.email, user.time_joined, None),
                                                          context)
        return await intermediate_handle_post_sign_in(user, context)

    return SignInFeature(disable_default_implementation, handle_post_sign_in)


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


def email_verification_create_and_send_custom_email(recipe: ThirdPartyEmailPasswordRecipe,
                                                    create_and_send_custom_email):
    async def func(user, link):
        user_info = await recipe.get_user_by_id(user.id)
        if user_info is None:
            raise_unknown_user_id_exception(recipe, 'User ID unknown')
        return await create_and_send_custom_email(user_info, link)

    return func


def email_verification_get_email_verification_url(recipe: ThirdPartyEmailPasswordRecipe, get_email_verification_url):
    async def func(user):
        user_info = await recipe.get_user_by_id(user.id)
        if user_info is None:
            raise_unknown_user_id_exception(recipe, 'User ID unknown')
        return await get_email_verification_url(user_info)

    return func


def email_verification_handle_post_email_verification(recipe: ThirdPartyEmailPasswordRecipe,
                                                      handle_post_email_verification):
    async def func(user):
        user_info = await recipe.get_user_by_id(user.id)
        if user_info is None:
            raise_unknown_user_id_exception(recipe, 'User ID unknown')
        return await handle_post_email_verification(user_info)

    return func


def validate_and_normalise_email_verification_config(recipe: ThirdPartyEmailPasswordRecipe, config=None):
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


class ThirdPartyEmailPasswordConfig:
    def __init__(self,
                 session_feature: SessionFeature,
                 sign_in_feature: SignInFeature,
                 sign_up_feature: SignUpFeature,
                 sign_out_feature: SignOutFeature,
                 email_verification_feature: any,
                 providers: List,
                 reset_password_using_token_feature: any):
        self.session_feature = session_feature
        self.sign_in_feature = sign_in_feature
        self.sign_up_feature = sign_up_feature
        self.sign_out_feature = sign_out_feature
        self.email_verification_feature = email_verification_feature
        self.providers = providers
        self.reset_password_using_token_feature = reset_password_using_token_feature


def validate_and_normalise_user_input(recipe: ThirdPartyEmailPasswordRecipe, config) -> ThirdPartyEmailPasswordConfig:
    validate_the_structure_of_user_input(config, INPUT_SCHEMA, 'thirdpartyemailpassword recipe', recipe)
    session_feature = validate_and_normalise_session_feature_config(
        config['session_feature'] if 'session_feature' in config else None)
    sign_in_feature = validate_and_normalise_sign_in_config(
        config['sign_in_feature'] if 'sign_in_feature' in config else None)
    sign_up_feature = validate_and_normalise_sign_up_config(
        config['sign_up_feature'] if 'sign_up_feature' in config else None)
    sign_out_feature = validate_and_normalise_sign_out_config(
        config['sign_out_feature'] if 'sign_out_feature' in config else None)
    email_verification_feature = validate_and_normalise_email_verification_config(
        recipe,
        config['email_verification_feature'] if 'email_verification_feature' in config else None)
    providers = config['providers'] if 'providers' in config else []
    reset_password_using_token_feature = config[
        'reset_password_using_token_feature'] if 'reset_password_using_token_feature' in config else {}
    return ThirdPartyEmailPasswordConfig(session_feature, sign_in_feature, sign_up_feature, sign_out_feature,
                                         email_verification_feature, providers, reset_password_using_token_feature)


def create_new_pagination_token(user_id: str, time_joined: int) -> str:
    return b64encode(user_id + ';' + str(time_joined))


def combine_pagination_tokens(third_party_pagination_token: Union[str, None],
                              email_password_pagination_token: Union[str, None]):
    if third_party_pagination_token is None:
        third_party_pagination_token = 'null'
    if email_password_pagination_token is None:
        email_password_pagination_token = 'null'
    return b64encode(third_party_pagination_token + ';' + email_password_pagination_token)


def extract_pagination_token(recipe: ThirdPartyEmailPasswordRecipe, next_pagination_token: str) -> NextPaginationToken:
    extracted_tokens = b64decode(next_pagination_token).split(';')
    if len(extracted_tokens) != 2:
        raise_invalid_pagination_token_exception(recipe, 'nextPaginationToken is invalid')
    return NextPaginationToken(None if extracted_tokens[0] == 'null' else extracted_tokens[0],
                               None if extracted_tokens[1] == 'null' else extracted_tokens[1])


def combine_pagination_results(third_party_result: UsersResponse, email_password_result: UsersResponse, limit: int,
                               oldest_first: bool) -> UsersResponse:
    max_loop = min(limit, len(third_party_result.users), len(email_password_result.users))
    third_party_result_loop_index = 0
    email_password_result_loop_index = 0
    users = []
    for i in range(max_loop):
        if (
                third_party_result_loop_index != len(third_party_result.users)
                and
                (
                    email_password_result_loop_index == len(email_password_result.users)
                    or
                    (
                        oldest_first and third_party_result.users[third_party_result_loop_index].time_joined <
                        email_password_result.users[email_password_result_loop_index].time_joined
                    )
                    or
                    (
                        not oldest_first and third_party_result.users[
                            third_party_result_loop_index].time_joined >
                        email_password_result.users[email_password_result_loop_index].time_joined
                    )
                )
        ):
            users.append(third_party_result.users[third_party_result_loop_index])
            third_party_result_loop_index += 1
        else:
            users.append(email_password_result.users[third_party_result_loop_index])
            email_password_result_loop_index += 1

    if third_party_result_loop_index == len(third_party_result.users):
        third_party_pagination_token = third_party_result.next_pagination_token
    else:
        third_party_pagination_token = create_new_pagination_token(
            third_party_result.users[third_party_result_loop_index].user_id,
            third_party_result.users[third_party_result_loop_index].time_joined
        )
    if email_password_result_loop_index == len(email_password_result.users):
        email_password_pagination_token = email_password_result.next_pagination_token
    else:
        email_password_pagination_token = create_new_pagination_token(
            email_password_result.users[email_password_result_loop_index].user_id,
            email_password_result.users[email_password_result_loop_index].time_joined
        )
    next_pagination_token = combine_pagination_tokens(third_party_pagination_token, email_password_pagination_token)
    return UsersResponse(users, next_pagination_token)
