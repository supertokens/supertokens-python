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
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union

from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.types import APIResponse, GeneralErrorResponse

from .utils import JWTConfig


class JsonWebKey:
    def __init__(self, kty: str, kid: str, n: str, e: str, alg: str, use: str):
        self.kty = kty
        self.kid = kid
        self.n = n
        self.e = e
        self.alg = alg
        self.use = use


class CreateJwtOkResult:
    def __init__(self, jwt: str):
        self.jwt = jwt


class CreateJwtResultUnsupportedAlgorithm:
    pass


class GetJWKSResult:
    def __init__(self, keys: List[JsonWebKey]):
        self.keys = keys


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_jwt(
        self,
        payload: Dict[str, Any],
        validity_seconds: Union[int, None],
        user_context: Dict[str, Any],
    ) -> Union[CreateJwtOkResult, CreateJwtResultUnsupportedAlgorithm]:
        pass

    @abstractmethod
    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: JWTConfig,
        recipe_implementation: RecipeInterface,
    ):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class JWKSGetResponse(APIResponse):
    status: str = "OK"

    def __init__(self, keys: List[JsonWebKey]):
        self.keys = keys

    def to_json(self) -> Dict[str, Any]:
        keys: List[Dict[str, Any]] = []
        for key in self.keys:
            keys.append(
                {
                    "kty": key.kty,
                    "kid": key.kid,
                    "n": key.n,
                    "e": key.e,
                    "alg": key.alg,
                    "use": key.use,
                }
            )

        return {"status": self.status, "keys": keys}


class APIInterface:
    def __init__(self):
        self.disable_jwks_get = False

    @abstractmethod
    async def jwks_get(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> Union[JWKSGetResponse, GeneralErrorResponse]:
        pass
