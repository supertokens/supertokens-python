# Copyright (c) 2023, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import Optional, Dict, Any

from supertokens_python.recipe.thirdparty.provider import (
    Provider,
    ProviderConfigForClient,
)
from .custom import GenericProvider, NewProvider
from ..provider import Provider, ProviderInput
from .utils import normalise_oidc_endpoint_to_include_well_known
from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath


class GitlabImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["openid", "email"]

        if (
            config.additional_config is not None
            and config.additional_config.get("gitlabBaseUrl") is not None
        ):
            gitlab_base_url = config.additional_config["gitlabBaseUrl"]
            oidc_domain = NormalisedURLDomain(gitlab_base_url)
            oidc_path = NormalisedURLPath("/.well-known/openid-configuration")
            config.oidc_discovery_endpoint = (
                oidc_domain.get_as_string_dangerous()
                + oidc_path.get_as_string_dangerous()
            )

        if not config.oidc_discovery_endpoint:
            raise Exception("should never come here")

        # The config could be coming from core where we didn't add the well-known previously
        config.oidc_discovery_endpoint = normalise_oidc_endpoint_to_include_well_known(
            config.oidc_discovery_endpoint
        )

        return config


def Gitlab(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if not input.config.name:
        input.config.name = "Gitlab"

    if not input.config.oidc_discovery_endpoint:
        input.config.oidc_discovery_endpoint = (
            "https://gitlab.com/.well-known/openid-configuration"
        )

    return NewProvider(input, GitlabImpl)
