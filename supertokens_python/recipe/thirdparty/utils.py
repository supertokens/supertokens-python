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

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from jwt import PyJWKClient, decode  # type: ignore

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.thirdparty.provider import ProviderInput
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
    BaseOverrideConfig,
)

from .interfaces import APIInterface, RecipeInterface

if TYPE_CHECKING:
    from .provider import ProviderInput


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


ThirdPartyOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedThirdPartyOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
InputOverrideConfig = ThirdPartyOverrideConfig
"""Deprecated: Use `ThirdPartyOverrideConfig` instead."""


class ThirdPartyOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    sign_in_and_up_feature: SignInAndUpFeature


class ThirdPartyConfig(
    ThirdPartyOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, ThirdPartyOverrideableConfig],
):
    def to_overrideable_config(self) -> ThirdPartyOverrideableConfig:
        """Create a `ThirdPartyOverrideableConfig` from the current config."""
        return ThirdPartyOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: ThirdPartyOverrideableConfig,
    ) -> "ThirdPartyConfig":
        """
        Create a `ThirdPartyConfig` from a `ThirdPartyOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return ThirdPartyConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedThirdPartyConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    sign_in_and_up_feature: SignInAndUpFeature


def validate_and_normalise_user_input(
    config: ThirdPartyConfig,
) -> NormalisedThirdPartyConfig:
    if not isinstance(config.sign_in_and_up_feature, SignInAndUpFeature):  # type: ignore
        raise ValueError(
            "sign_in_and_up_feature must be an instance of SignInAndUpFeature"
        )

    override_config = NormalisedThirdPartyOverrideConfig.from_input_config(
        override_config=config.override
    )

    return NormalisedThirdPartyConfig(
        sign_in_and_up_feature=config.sign_in_and_up_feature,
        override=override_config,
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
