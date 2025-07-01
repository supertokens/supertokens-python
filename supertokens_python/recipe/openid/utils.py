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

from typing import TYPE_CHECKING, Optional, Union

from supertokens_python.recipe.jwt import OverrideConfig as JWTOverrideConfig
from supertokens_python.types.config import (
    BaseConfig,
    BaseInputConfig,
    BaseInputOverrideConfig,
    BaseOverrideConfig,
)
from supertokens_python.types.utils import UseDefaultIfNone

if TYPE_CHECKING:
    from supertokens_python import AppInfo


from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath

from .interfaces import APIInterface, RecipeInterface


class InputOverrideConfig(BaseInputOverrideConfig[RecipeInterface, APIInterface]):
    jwt_feature: Union[JWTOverrideConfig, None] = None


class OverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]): ...


class OpenIdInputConfig(BaseInputConfig[RecipeInterface, APIInterface]):
    issuer: Union[str, None] = None
    override: UseDefaultIfNone[Optional[InputOverrideConfig]] = InputOverrideConfig()  # type: ignore - https://github.com/microsoft/pyright/issues/5933


class OpenIdConfig(BaseConfig[RecipeInterface, APIInterface]):
    issuer_domain: NormalisedURLDomain
    issuer_path: NormalisedURLPath
    override: OverrideConfig  # type: ignore - https://github.com/microsoft/pyright/issues/5933


def validate_and_normalise_user_input(
    app_info: AppInfo,
    input_config: OpenIdInputConfig,
) -> OpenIdConfig:
    if input_config.issuer is None:
        issuer_domain = app_info.api_domain
        issuer_path = app_info.api_base_path
    else:
        issuer_domain = NormalisedURLDomain(input_config.issuer)
        issuer_path = NormalisedURLPath(input_config.issuer)

    if not issuer_path.equals(app_info.api_base_path):
        raise Exception(
            "The path of the issuer URL must be equal to the apiBasePath. The default value is /auth"
        )

    override_config = OverrideConfig()
    if input_config.override is not None:
        if input_config.override.functions is not None:
            override_config.functions = input_config.override.functions

        if input_config.override.apis is not None:
            override_config.apis = input_config.override.apis

    return OpenIdConfig(
        issuer_domain=issuer_domain,
        issuer_path=issuer_path,
        override=override_config,
    )
