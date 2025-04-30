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
from typing import Any, Dict, List, Optional, Union

from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.recipe.jwt.interfaces import (
    CreateJwtOkResult,
    CreateJwtResultUnsupportedAlgorithm,
    GetJWKSResult,
)
from supertokens_python.types.response import APIResponse, GeneralErrorResponse

from .utils import OpenIdConfig


class GetOpenIdDiscoveryConfigurationResult:
    def __init__(
        self,
        issuer: str,
        jwks_uri: str,
        authorization_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str,
        revocation_endpoint: str,
        token_introspection_endpoint: str,
        end_session_endpoint: str,
        subject_types_supported: List[str],
        id_token_signing_alg_values_supported: List[str],
        response_types_supported: List[str],
    ):
        self.issuer = issuer
        self.jwks_uri = jwks_uri
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.revocation_endpoint = revocation_endpoint
        self.token_introspection_endpoint = token_introspection_endpoint
        self.end_session_endpoint = end_session_endpoint
        self.subject_types_supported = subject_types_supported
        self.id_token_signing_alg_values_supported = (
            id_token_signing_alg_values_supported
        )
        self.response_types_supported = response_types_supported

    def to_json(self) -> Dict[str, Any]:
        return {
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "revocation_endpoint": self.revocation_endpoint,
            "token_introspection_endpoint": self.token_introspection_endpoint,
            "end_session_endpoint": self.end_session_endpoint,
            "subject_types_supported": self.subject_types_supported,
            "id_token_signing_alg_values_supported": self.id_token_signing_alg_values_supported,
            "response_types_supported": self.response_types_supported,
        }


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_jwt(
        self,
        payload: Dict[str, Any],
        validity_seconds: Optional[int],
        use_static_signing_key: Optional[bool],
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

    def __init__(
        self,
        issuer: str,
        jwks_uri: str,
        authorization_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str,
        revocation_endpoint: str,
        token_introspection_endpoint: str,
        end_session_endpoint: str,
        subject_types_supported: List[str],
        id_token_signing_alg_values_supported: List[str],
        response_types_supported: List[str],
    ):
        self.issuer = issuer
        self.jwks_uri = jwks_uri
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.revocation_endpoint = revocation_endpoint
        self.token_introspection_endpoint = token_introspection_endpoint
        self.end_session_endpoint = end_session_endpoint
        self.subject_types_supported = subject_types_supported
        self.id_token_signing_alg_values_supported = (
            id_token_signing_alg_values_supported
        )
        self.response_types_supported = response_types_supported

    def to_json(self):
        return {
            "status": self.status,
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "revocation_endpoint": self.revocation_endpoint,
            "token_introspection_endpoint": self.token_introspection_endpoint,
            "end_session_endpoint": self.end_session_endpoint,
            "subject_types_supported": self.subject_types_supported,
            "id_token_signing_alg_values_supported": self.id_token_signing_alg_values_supported,
            "response_types_supported": self.response_types_supported,
        }


class APIInterface:
    def __init__(self):
        self.disable_open_id_discovery_configuration_get = False

    @abstractmethod
    async def open_id_discovery_configuration_get(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> Union[OpenIdDiscoveryConfigurationGetResponse, GeneralErrorResponse]:
        pass
