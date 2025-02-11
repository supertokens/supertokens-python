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

from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from supertokens_python.querier import Querier

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from .interfaces import CreateJwtOkResult, CreateJwtResultUnsupportedAlgorithm
    from .utils import OpenIdConfig

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.jwt.constants import GET_JWKS_API

from ..jwt.recipe import JWTRecipe
from .interfaces import (
    GetJWKSResult,
    GetOpenIdDiscoveryConfigurationResult,
    RecipeInterface,
)


class RecipeImplementation(RecipeInterface):
    async def get_open_id_discovery_configuration(
        self, user_context: Dict[str, Any]
    ) -> GetOpenIdDiscoveryConfigurationResult:
        from ..oauth2provider.constants import (
            AUTH_PATH,
            END_SESSION_PATH,
            INTROSPECT_TOKEN_PATH,
            REVOKE_TOKEN_PATH,
            TOKEN_PATH,
            USER_INFO_PATH,
        )

        issuer = (
            self.app_info.api_domain.get_as_string_dangerous()
            + self.app_info.api_base_path.get_as_string_dangerous()
        )

        jwks_uri = (
            self.app_info.api_domain.get_as_string_dangerous()
            + self.app_info.api_base_path.append(
                NormalisedURLPath(GET_JWKS_API)
            ).get_as_string_dangerous()
        )

        api_base_path: str = (
            self.app_info.api_domain.get_as_string_dangerous()
            + self.app_info.api_base_path.get_as_string_dangerous()
        )

        return GetOpenIdDiscoveryConfigurationResult(
            issuer=issuer,
            jwks_uri=jwks_uri,
            authorization_endpoint=api_base_path + AUTH_PATH,
            token_endpoint=api_base_path + TOKEN_PATH,
            userinfo_endpoint=api_base_path + USER_INFO_PATH,
            revocation_endpoint=api_base_path + REVOKE_TOKEN_PATH,
            token_introspection_endpoint=api_base_path + INTROSPECT_TOKEN_PATH,
            end_session_endpoint=api_base_path + END_SESSION_PATH,
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
            response_types_supported=["code", "id_token", "id_token token"],
        )

    def __init__(
        self,
        querier: Querier,
        config: OpenIdConfig,
        app_info: AppInfo,
    ):
        super().__init__()
        self.querier = querier
        self.config = config
        self.app_info = app_info

    async def create_jwt(
        self,
        payload: Dict[str, Any],
        validity_seconds: Optional[int],
        use_static_signing_key: Optional[bool],
        user_context: Dict[str, Any],
    ) -> Union[CreateJwtOkResult, CreateJwtResultUnsupportedAlgorithm]:
        jwt_recipe = JWTRecipe.get_instance()
        issuer = (
            self.config.issuer_domain.get_as_string_dangerous()
            + self.config.issuer_path.get_as_string_dangerous()
        )
        payload = {"iss": issuer, **payload}
        return await jwt_recipe.recipe_implementation.create_jwt(
            payload, validity_seconds, use_static_signing_key, user_context
        )

    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult:
        jwt_recipe = JWTRecipe.get_instance()
        return await jwt_recipe.recipe_implementation.get_jwks(user_context)
