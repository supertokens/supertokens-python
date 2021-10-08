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
from typing import Literal, Union, Callable

from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.recipe.jwt.interfaces import RecipeInterface, APIInterface


class JsonWebKey:
    def __init__(self):
        self.kty = None
        self.kid = None
        self.n = None
        self.e = None
        self.alg = None
        self.use = None


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None],
                 apis: Union[Callable[[APIInterface], APIInterface], None]):
        self.functions = functions
        self.apis = apis


class JWTConfig:
    def __init__(self, override, jwt_validity_seconds: int = 3153600000):
        self.override = override
        self.jwt_validity_seconds = jwt_validity_seconds


class TypeInput:
    def __init__(self, override: OverrideConfig = None, jwt_validity_seconds: int = 3153600000):
        self.jwt_validity_seconds = jwt_validity_seconds
        self.override: OverrideConfig = override


class TypeNormalisedInput:
    def __init__(self, override: OverrideConfig, jwt_validity_seconds: int = 3153600000):
        self.jwt_validity_seconds = jwt_validity_seconds
        self.override: OverrideConfig = override


class APIOptions:
    def __init__(self, request: BaseRequest, response: Union[BaseResponse, None], recipe_id: str,
                 config, recipe_implementation: RecipeInterface):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class CreateJwtResult:
    def __init__(
            self, status: Literal['OK', 'UNSUPPORTED_ALGORITHM_ERROR'], jwt: str = None):
        self.status = status
        self.jwt = jwt


class GetJWKSResult:
    def __init__(
            self, status: Literal['OK'], keys: []):
        self.status = status
        self.keys = keys
