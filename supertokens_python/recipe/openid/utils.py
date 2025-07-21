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

from typing import TYPE_CHECKING, Optional

from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideConfig,
)

from .interfaces import APIInterface, RecipeInterface

if TYPE_CHECKING:
    from supertokens_python import AppInfo


OpenIdOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedOpenIdOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]


class OpenIdConfig(BaseConfig[RecipeInterface, APIInterface]):
    issuer: Optional[str] = None


class NormalisedOpenIdConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    issuer_domain: NormalisedURLDomain
    issuer_path: NormalisedURLPath


def validate_and_normalise_user_input(
    app_info: AppInfo,
    config: OpenIdConfig,
) -> NormalisedOpenIdConfig:
    if config.issuer is None:
        issuer_domain = app_info.api_domain
        issuer_path = app_info.api_base_path
    else:
        issuer_domain = NormalisedURLDomain(config.issuer)
        issuer_path = NormalisedURLPath(config.issuer)

    if not issuer_path.equals(app_info.api_base_path):
        raise Exception(
            "The path of the issuer URL must be equal to the apiBasePath. The default value is /auth"
        )

    override_config = NormalisedOpenIdOverrideConfig.from_input_config(
        override_config=config.override
    )

    return NormalisedOpenIdConfig(
        issuer_domain=issuer_domain,
        issuer_path=issuer_path,
        override=override_config,
    )
