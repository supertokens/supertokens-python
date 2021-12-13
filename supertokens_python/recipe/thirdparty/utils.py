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

from typing import List, Callable, TYPE_CHECKING, Union

from .interfaces import RecipeInterface, APIInterface
from supertokens_python.exceptions import raise_bad_input_exception

if TYPE_CHECKING:
    from .recipe import ThirdPartyRecipe
    from .provider import Provider
from supertokens_python.recipe.emailverification.utils import (
    InputEmailVerificationConfig, ParentRecipeEmailVerificationConfig,
    OverrideConfig as EmailVerificationOverrideConfig
)
from jwt import PyJWKClient, decode


class SignInAndUpFeature:
    def __init__(self, providers: List[Provider]):
        if len(providers) == 0:
            raise_bad_input_exception('thirdparty recipe requires atleast 1 provider to be passed in '
                                      'sign_in_and_up_feature.providers config')
        default_providers_set = set()
        all_providers_set = set()

        for provider in providers:
            provider_id = provider.id
            all_providers_set.add(provider_id)
            is_default = provider.is_default

            if not is_default:
                # if this id is not being used by any other provider, we treat this as the is_default
                other_providers_with_same_id = list(filter(lambda p: p.id == provider_id and provider != p, providers))
                if len(other_providers_with_same_id) == 0:
                    # we treat this as the isDefault now.
                    is_default = True
            if is_default:
                if provider_id in default_providers_set:
                    raise_bad_input_exception(
                        'You have provided multiple third party providers that have the id: "' + provider_id + '" '
                                                                                                               'and '
                                                                                                               'are '
                                                                                                               'marked as "is_default: True". Please only mark one of them as is_default.')
                default_providers_set.add(provider_id)

        if len(default_providers_set) != len(all_providers_set):
            # this means that there is no provider marked as is_default
            raise_bad_input_exception(
                'The providers array has multiple entries for the same third party provider. Please '
                'mark one of them as the default one by using "is_default: true".')
        self.providers = providers


def email_verification_create_and_send_custom_email(
        recipe: ThirdPartyRecipe, create_and_send_custom_email):
    async def func(user, link):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.id)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return await create_and_send_custom_email(user_info, link)

    return func


def email_verification_get_email_verification_url(
        recipe: ThirdPartyRecipe, get_email_verification_url):
    async def func(user):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.id)
        if user_info is None:
            raise Exception(recipe, 'Unknown User ID provided')
        return await get_email_verification_url(user_info)

    return func


def validate_and_normalise_email_verification_config(
        recipe: ThirdPartyRecipe, config: Union[InputEmailVerificationConfig, None], override: InputOverrideConfig)\
        -> ParentRecipeEmailVerificationConfig:
    create_and_send_custom_email = None
    get_email_verification_url = None
    if config is None:
        config = InputEmailVerificationConfig()
    if config.create_and_send_custom_email is not None:
        create_and_send_custom_email = email_verification_create_and_send_custom_email(recipe, config.create_and_send_custom_email)
    if config.get_email_verification_url is not None:
        get_email_verification_url = email_verification_get_email_verification_url(recipe,
                                                                                   config.get_email_verification_url)

    return ParentRecipeEmailVerificationConfig(
        get_email_for_user_id=recipe.get_email_for_user_id,
        create_and_send_custom_email=create_and_send_custom_email,
        get_email_verification_url=get_email_verification_url,
        override=override.email_verification_feature
    )


class InputOverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
                 apis: Union[Callable[[APIInterface], APIInterface], None] = None,
                 email_verification_feature: Union[EmailVerificationOverrideConfig, None] = None):
        self.functions = functions
        self.apis = apis
        self.email_verification_feature = email_verification_feature


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
                 apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        self.functions = functions
        self.apis = apis


class ThirdPartyConfig:
    def __init__(self,
                 sign_in_and_up_feature: SignInAndUpFeature,
                 email_verification_feature: ParentRecipeEmailVerificationConfig,
                 override: OverrideConfig):
        self.sign_in_and_up_feature = sign_in_and_up_feature
        self.email_verification_feature = email_verification_feature
        self.override = override


def validate_and_normalise_user_input(
        recipe: ThirdPartyRecipe,
        sign_in_and_up_feature: SignInAndUpFeature,
        email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
        override: Union[InputOverrideConfig, None] = None) -> ThirdPartyConfig:
    if override is None:
        override = InputOverrideConfig()
    email_verification_feature = validate_and_normalise_email_verification_config(
        recipe,
        email_verification_feature, override)
    return ThirdPartyConfig(sign_in_and_up_feature, email_verification_feature,
                            OverrideConfig(functions=override.functions, apis=override.apis)
                            )


def find_right_provider(
        providers: List[Provider],
        third_party_id: str,
        client_id: Union[str, None]
) -> Union[Provider, None]:
    for provider in providers:
        provider_id = provider.id
        if provider_id != third_party_id:
            continue

        # first if there is only one provider with third_party_id in the providers array
        other_providers_with_same_id = list(filter(lambda p: p.id == provider_id and provider != p, providers))
        if len(other_providers_with_same_id) == 0:
            # then we always return that.
            return provider

        # otherwise, we look for the is_default provider if client_id is missing
        if client_id is None and provider.is_default:
            return provider

        # otherwise, we return a provider that matches based on client Id as well.
        if provider.client_id == client_id:
            return provider

    return None


def verify_id_token_from_jwks_endpoint(id_token: str, jwks_uri: str, audience: str, issuers: List[str]):
    jwks_client = PyJWKClient(jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    data = decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=audience,
        options={"verify_exp": False})

    issuer_found = False
    for issuer in issuers:
        if data['iss'] == issuer:
            issuer_found = True

    if not issuer_found:
        raise Exception('no required issuer found')

    return data
