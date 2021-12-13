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

from supertokens_python.querier import Querier
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .utils import OpenIdConfig
    from .interfaces import CreateJwtResult
    from supertokens_python.supertokens import AppInfo
from .interfaces import RecipeInterface, GetJWKSResult
from supertokens_python.recipe.jwt.interfaces import RecipeInterface as JWTRecipeInterface
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.jwt.constants import GET_JWKS_API
from .interfaces import GetOpenIdDiscoveryConfigurationResult


class RecipeImplementation(RecipeInterface):

    async def get_open_id_discovery_configuration(self) -> GetOpenIdDiscoveryConfigurationResult:
        issuer = self.config.issuer_domain.get_as_string_dangerous() + self.config.issuer_path.get_as_string_dangerous()

        jwks_uri = self.config.issuer_domain.get_as_string_dangerous() + self.config.issuer_path.append(
            NormalisedURLPath(GET_JWKS_API)).get_as_string_dangerous()

        return GetOpenIdDiscoveryConfigurationResult('OK', issuer, jwks_uri)

    def __init__(self, querier: Querier, config: OpenIdConfig, app_info: AppInfo, jwt_recipe_implementation: JWTRecipeInterface):
        super().__init__()
        self.querier = querier
        self.config = config
        self.app_info = app_info
        self.jwt_recipe_implementation = jwt_recipe_implementation

    async def create_jwt(self, payload: dict = None, validity_seconds: int = None) -> CreateJwtResult:
        if payload is None:
            payload = {}

        issuer = self.config.issuer_domain.get_as_string_dangerous() + self.config.issuer_path.get_as_string_dangerous()
        payload = {
            'iss': issuer,
            **payload
        }
        return await self.jwt_recipe_implementation.create_jwt(payload, validity_seconds)

    async def get_jwks(self) -> GetJWKSResult:
        return await self.jwt_recipe_implementation.get_jwks()
