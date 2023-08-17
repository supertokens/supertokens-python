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

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Set, Union, Optional

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.thirdparty.provider import ProviderInput

from .interfaces import APIInterface, RecipeInterface

if TYPE_CHECKING:
    from .provider import ProviderInput

from jwt import PyJWKClient, decode  # type: ignore


class SignInAndUpFeature:
    def __init__(self, providers: Optional[List[ProviderInput]] = None):
        if providers is None:
            providers = []

        third_party_id_set: Set[str] = set()

        for provider in providers:
            third_party_id = provider.config.third_party_id

            if third_party_id in third_party_id_set:
                raise_bad_input_exception(
                    "The providers array has multiple entries for the same third party provider."
                )

            third_party_id_set.add(third_party_id)

        self.providers = providers


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class ThirdPartyConfig:
    def __init__(
        self,
        sign_in_and_up_feature: SignInAndUpFeature,
        override: OverrideConfig,
    ):
        self.sign_in_and_up_feature = sign_in_and_up_feature
        self.override = override


def validate_and_normalise_user_input(
    sign_in_and_up_feature: SignInAndUpFeature,
    override: Union[InputOverrideConfig, None] = None,
) -> ThirdPartyConfig:
    if not isinstance(sign_in_and_up_feature, SignInAndUpFeature):  # type: ignore
        raise ValueError(
            "sign_in_and_up_feature must be an instance of SignInAndUpFeature"
        )

    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be an instance of InputOverrideConfig or None")

    if override is None:
        override = InputOverrideConfig()

    return ThirdPartyConfig(
        sign_in_and_up_feature,
        OverrideConfig(functions=override.functions, apis=override.apis),
    )


def verify_id_token_from_jwks_endpoint(
    id_token: str, jwks_uri: str, audience: str, issuers: List[str]
) -> Dict[str, Any]:
    jwks_client = PyJWKClient(jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    data: Dict[str, Any] = decode(  # type: ignore
        id_token,
        signing_key.key,  # type: ignore
        algorithms=["RS256"],
        audience=audience,
        options={"verify_exp": False},
    )

    issuer_found = False
    for issuer in issuers:
        if data["iss"] == issuer:
            issuer_found = True

    if not issuer_found:
        raise Exception("no required issuer found")

    return data
