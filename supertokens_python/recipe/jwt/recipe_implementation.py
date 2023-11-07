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

from typing import TYPE_CHECKING, Any, Dict, List, Union, Optional

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
import re

if TYPE_CHECKING:
    from .utils import JWTConfig
    from supertokens_python.supertokens import AppInfo

from supertokens_python.recipe.jwt.interfaces import (
    CreateJwtOkResult,
    CreateJwtResultUnsupportedAlgorithm,
    GetJWKSResult,
    RecipeInterface,
)

from .interfaces import JsonWebKey


# This corresponds to the dynamicSigningKeyOverlapMS in the core
DEFAULT_JWKS_MAX_AGE = 60


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, config: JWTConfig, app_info: AppInfo):
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
        if validity_seconds is None:
            validity_seconds = self.config.jwt_validity_seconds

        data = {
            "payload": payload,
            "validity": validity_seconds,
            "useStaticSigningKey": use_static_signing_key is not False,
            "algorithm": "RS256",
            "jwksDomain": self.app_info.api_domain.get_as_string_dangerous(),
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/jwt"),
            data,
            user_context=user_context,
        )

        if response["status"] == "OK":
            return CreateJwtOkResult(response["jwt"])
        return CreateJwtResultUnsupportedAlgorithm()

    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/.well-known/jwks.json"),
            {},
            user_context=user_context,
        )

        validity_in_secs = DEFAULT_JWKS_MAX_AGE
        cache_control = response["_headers"].get("Cache-Control")

        if cache_control is not None:
            pattern = r",?\s*max-age=(\d+)(?:,|$)"
            max_age_header = re.match(pattern, cache_control)
            if max_age_header is not None:
                validity_in_secs = int(max_age_header.group(1))
                try:
                    validity_in_secs = int(validity_in_secs)
                except Exception:
                    validity_in_secs = DEFAULT_JWKS_MAX_AGE

        keys: List[JsonWebKey] = []
        for key in response["keys"]:
            keys.append(
                JsonWebKey(
                    key["kty"], key["kid"], key["n"], key["e"], key["alg"], key["use"]
                )
            )

        return GetJWKSResult(keys, validity_in_secs)
