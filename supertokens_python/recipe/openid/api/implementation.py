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
from typing import Any, Dict

from supertokens_python.recipe.openid.interfaces import (
    APIInterface,
    APIOptions,
    OpenIdDiscoveryConfigurationGetResponse,
)


class APIImplementation(APIInterface):
    async def open_id_discovery_configuration_get(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> OpenIdDiscoveryConfigurationGetResponse:
        response = (
            await api_options.recipe_implementation.get_open_id_discovery_configuration(
                user_context
            )
        )
        return OpenIdDiscoveryConfigurationGetResponse(
            response.issuer, response.jwks_uri
        )
