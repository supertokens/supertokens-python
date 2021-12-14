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

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .utils import JWTConfig
    from .interfaces import CreateJwtResult
    from supertokens_python.supertokens import AppInfo
from .types import JsonWebKey
from supertokens_python.recipe.jwt.interfaces import RecipeInterface, GetJWKSResult,\
    CreateJwtResultOk, CreateJwtResultUnsupportedAlgorithm


class RecipeImplementation(RecipeInterface):

    def __init__(self, querier: Querier, config: JWTConfig, app_info: AppInfo):
        super().__init__()
        self.querier = querier
        self.config = config
        self.app_info = app_info

    async def create_jwt(self, payload: dict = None, validity_seconds: int = None) -> CreateJwtResult:
        if validity_seconds is None:
            validity_seconds = self.config.jwt_validity_seconds

        if payload is None:
            payload = {}

        data = {
            'payload': payload,
            'validity': validity_seconds,
            'algorithm': 'RS256',
            'jwksDomain': self.app_info.api_domain.get_as_string_dangerous()
        }
        response = await self.querier.send_post_request(NormalisedURLPath("/recipe/jwt"), data)

        if response['status'] == 'OK':
            return CreateJwtResultOk(response['jwt'])
        else:
            return CreateJwtResultUnsupportedAlgorithm()

    async def get_jwks(self) -> GetJWKSResult:
        response = await self.querier.send_get_request(NormalisedURLPath("/recipe/jwt/jwks"), {})

        keys = []
        for key in response['keys']:
            keys.append(JsonWebKey(
                key['kty'],
                key['kid'],
                key['n'],
                key['e'],
                key['alg'],
                key['use']
            ))
        return GetJWKSResult(response['status'], keys)
