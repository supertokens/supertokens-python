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
from typing import Any, Dict, Union

from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.recipe.jwt.interfaces import (
    CreateJwtOkResult,
    CreateJwtResultUnsupportedAlgorithm,
    GetJWKSResult,
)
from supertokens_python.types import APIResponse, GeneralErrorResponse

from .utils import OpenIdConfig


class GetOpenIdDiscoveryConfigurationResult:
    def __init__(self, issuer: str, jwks_uri: str):
        self.issuer = issuer
        self.jwks_uri = jwks_uri


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

    @abstractmethod
    async def get_open_id_discovery_configuration(
        self, user_context: Dict[str, Any]
    ) -> GetOpenIdDiscoveryConfigurationResult:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: OpenIdConfig,
        recipe_implementation: RecipeInterface,
    ):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class OpenIdDiscoveryConfigurationGetResponse(APIResponse):
    status: str = "OK"

    def __init__(self, issuer: str, jwks_uri: str):
        self.issuer = issuer
        self.jwks_uri = jwks_uri

    def to_json(self):
        return {"status": self.status, "issuer": self.issuer, "jwks_uri": self.jwks_uri}


class APIInterface:
    def __init__(self):
        self.disable_open_id_discovery_configuration_get = False

    @abstractmethod
    async def open_id_discovery_configuration_get(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> Union[OpenIdDiscoveryConfigurationGetResponse, GeneralErrorResponse]:
        pass
