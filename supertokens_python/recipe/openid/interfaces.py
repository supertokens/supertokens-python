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
from supertokens_python.recipe.jwt.interfaces import (CreateJwtResult,
                                                      GetJWKSResult)
from typing_extensions import Literal

from .utils import OpenIdConfig


class GetOpenIdDiscoveryConfigurationResult(ABC):
    """GetOpenIdDiscoveryConfigurationResult.
    """

    def __init__(
            self, status: Literal['OK'], issuer: str, jwks_uri: str):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        issuer : str
            issuer
        jwks_uri : str
            jwks_uri
        """
        self.status = status
        self.issuer = issuer
        self.jwks_uri = jwks_uri


class RecipeInterface(ABC):
    """RecipeInterface.
    """

    def __init__(self):
        """__init__.
        """
        pass

    @abstractmethod
    async def create_jwt(self, payload: Dict[str, Any], validity_seconds: Union[int, None], user_context: Dict[str, Any]) -> CreateJwtResult:
        """create_jwt.

        Parameters
        ----------
        payload : Dict[str, Any]
            payload
        validity_seconds : Union[int, None]
            validity_seconds
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateJwtResult

        """
        pass

    @abstractmethod
    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult:
        """get_jwks.

        Parameters
        ----------
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        GetJWKSResult

        """
        pass

    @abstractmethod
    async def get_open_id_discovery_configuration(self, user_context: Dict[str, Any]) -> GetOpenIdDiscoveryConfigurationResult:
        """get_open_id_discovery_configuration.

        Parameters
        ----------
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        GetOpenIdDiscoveryConfigurationResult

        """
        pass


class APIOptions:
    """APIOptions.
    """

    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: OpenIdConfig, recipe_implementation: RecipeInterface):
        """__init__.

        Parameters
        ----------
        request : BaseRequest
            request
        response : BaseResponse
            response
        recipe_id : str
            recipe_id
        config : OpenIdConfig
            config
        recipe_implementation : RecipeInterface
            recipe_implementation
        """
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class OpenIdDiscoveryConfigurationGetResponse:
    """OpenIdDiscoveryConfigurationGetResponse.
    """

    def __init__(
            self, status: Literal['OK'], issuer: str, jwks_uri: str):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        issuer : str
            issuer
        jwks_uri : str
            jwks_uri
        """
        self.status = status
        self.issuer = issuer
        self.jwks_uri = jwks_uri

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'issuer': self.issuer,
            'jwks_uri': self.jwks_uri
        }


class APIInterface:
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
        self.disable_open_id_discovery_configuration_get = False

    @abstractmethod
    async def open_id_discovery_configuration_get(self, api_options: APIOptions, user_context: Dict[str, Any]) ->\
            OpenIdDiscoveryConfigurationGetResponse:
        """open_id_discovery_configuration_get.

        Parameters
        ----------
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        OpenIdDiscoveryConfigurationGetResponse

        """
        pass
