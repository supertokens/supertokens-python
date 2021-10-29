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
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal


class JsonWebKey:
    def __init__(self, kty: str, kid: str, n: str, e: str, alg: str, use: str):
        self.kty = kty
        self.kid = kid
        self.n = n
        self.e = e
        self.alg = alg
        self.use = use


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
