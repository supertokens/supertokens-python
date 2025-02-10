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
from __future__ import annotations

from typing import Any, Dict, Optional

from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath

from ..provider import (
    Provider,
    ProviderConfigForClient,
    ProviderInput,
)
from .custom import GenericProvider, NewProvider
from .utils import normalise_oidc_endpoint_to_include_well_known


class OktaImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if (
            config.additional_config is not None
            and config.additional_config.get("oktaDomain") is not None
        ):
            okta_domain = config.additional_config["oktaDomain"]
            oidc_domain = NormalisedURLDomain(okta_domain)
            oidc_path = NormalisedURLPath("/.well-known/openid-configuration")
            config.oidc_discovery_endpoint = (
                oidc_domain.get_as_string_dangerous()
                + oidc_path.get_as_string_dangerous()
            )

        if config.oidc_discovery_endpoint is not None:
            config.oidc_discovery_endpoint = (
                normalise_oidc_endpoint_to_include_well_known(
                    config.oidc_discovery_endpoint
                )
            )

        if config.scope is None:
            config.scope = ["openid", "email"]

        # TODO later if required, client assertion impl

        return config


def Okta(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if not input.config.name:
        input.config.name = "Okta"

    return NewProvider(input, OktaImpl)
