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
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.jwt.interfaces import RecipeInterface
from supertokens_python.recipe.jwt.types import TypeNormalisedInput, GetJWKSResult, CreateJwtResult
from supertokens_python.supertokens import AppInfo


class RecipeImplementation(RecipeInterface):

    def __init__(self, querier: Querier, config: TypeNormalisedInput, app_info: AppInfo):
        super().__init__()
        self.querier = querier
        self.config = config
        self.app_info = app_info

    async def create_jwt(self, payload=None, validity_seconds: int = None) -> [CreateJwtResult, None]:
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
            CreateJwtResult(status='OK', jwt=response['jwt'])
        else:
            CreateJwtResult(status='UNSUPPORTED_ALGORITHM_ERROR')

    async def get_JWKS(self) -> [GetJWKSResult, None]:
        response = await self.querier.send_get_request(NormalisedURLPath("/recipe/jwt/jwks"), {})

        return GetJWKSResult(response['status'], response['keys'])
