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
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.openid.interfaces import CreateJwtResult, GetJWKSResult, GetOpenIdDiscoveryConfigurationResult


async def create_jwt(payload: dict, validity_seconds: int = None) -> [CreateJwtResult, None]:
    return await OpenIdRecipe.get_instance().recipe_implementation.create_jwt(payload, validity_seconds)


async def get_jwks() -> [GetJWKSResult, None]:
    return await OpenIdRecipe.get_instance().recipe_implementation.get_jwks()


async def get_open_id_discovery_configuration() -> [GetOpenIdDiscoveryConfigurationResult, None]:
    return await OpenIdRecipe.get_instance().recipe_implementation.get_open_id_discovery_configuration()
