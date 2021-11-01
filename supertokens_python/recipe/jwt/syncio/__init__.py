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
from supertokens_python.recipe.jwt.recipe import JWTRecipe
from supertokens_python.recipe.jwt.types import CreateJwtResult, GetJWKSResult
import supertokens_python.recipe.jwt.asyncio as asyncio
from supertokens_python.async_to_sync_wrapper import sync


def create_jwt(payload: dict, validity_seconds: int = None) -> [CreateJwtResult, None]:
    return sync(asyncio.create_jwt(payload, validity_seconds))


def get_jwks() -> [GetJWKSResult, None]:
    return sync(asyncio.get_jwks())
