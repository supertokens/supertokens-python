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

from .utils import JWTConfig

from typing_extensions import Literal

from supertokens_python.framework import BaseRequest, BaseResponse


class JsonWebKey:
    """JsonWebKey.
    """

    def __init__(self, kty: str, kid: str, n: str, e: str, alg: str, use: str):
        """__init__.

        Parameters
        ----------
        kty : str
            kty
        kid : str
            kid
        n : str
            n
        e : str
            e
        alg : str
            alg
        use : str
            use
        """
        self.kty = kty
        self.kid = kid
        self.n = n
        self.e = e
        self.alg = alg
        self.use = use


class CreateJwtResult(ABC):
    """CreateJwtResult.
    """

    def __init__(
            self, status: Literal['OK', 'UNSUPPORTED_ALGORITHM_ERROR'], jwt: Union[None, str] = None):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'UNSUPPORTED_ALGORITHM_ERROR']
            status
        jwt : Union[None, str]
            jwt
        """
        self.status = status
        self.jwt = jwt


class CreateJwtResultOk(CreateJwtResult):
    """CreateJwtResultOk.
    """

    def __init__(self, jwt: str):
        """__init__.

        Parameters
        ----------
        jwt : str
            jwt
        """
        super().__init__('OK', jwt)


class CreateJwtResultUnsupportedAlgorithm(CreateJwtResult):
    """CreateJwtResultUnsupportedAlgorithm.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('UNSUPPORTED_ALGORITHM_ERROR')


class GetJWKSResult(ABC):
    """GetJWKSResult.
    """

    def __init__(
            self, status: Literal['OK'], keys: List[JsonWebKey]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        keys : List[JsonWebKey]
            keys
        """
        self.status = status
        self.keys = keys


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


class APIOptions:
    """APIOptions.
    """

    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: JWTConfig, recipe_implementation: RecipeInterface):
        """__init__.

        Parameters
        ----------
        request : BaseRequest
            request
        response : BaseResponse
            response
        recipe_id : str
            recipe_id
        config : JWTConfig
            config
        recipe_implementation : RecipeInterface
            recipe_implementation
        """
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class JWKSGetResponse:
    """JWKSGetResponse.
    """

    def __init__(
            self, status: Literal['OK'], keys: List[JsonWebKey]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        keys : List[JsonWebKey]
            keys
        """
        self.status = status
        self.keys = keys

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        keys: List[Dict[str, Any]] = []
        for key in self.keys:
            keys.append({
                'kty': key.kty,
                'kid': key.kid,
                'n': key.n,
                'e': key.e,
                'alg': key.alg,
                'use': key.use,
            })

        return {
            'status': 'OK',
            'keys': keys
        }


class APIInterface:
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
        self.disable_jwks_get = False

    @abstractmethod
    async def jwks_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> JWKSGetResponse:
        """jwks_get.

        Parameters
        ----------
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        JWKSGetResponse

        """
        pass
