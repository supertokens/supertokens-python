# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

import asyncio
import json
from typing import Any, Dict, Union

from supertokens_python.exceptions import BadInputError
from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_third_party_config,
    get_tenant,
)
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.thirdparty import ProviderConfig
from supertokens_python.recipe.thirdparty.providers.utils import do_post_request
from supertokens_python.types.response import APIResponse
from supertokens_python.utils import encode_base64

from ...interfaces import APIInterface, APIOptions


class CreateOrUpdateThirdPartyConfigOkResult(APIResponse):
    def __init__(self, created_new: bool):
        self.status = "OK"
        self.created_new = created_new

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "createdNew": self.created_new}


class CreateOrUpdateThirdPartyConfigUnknownTenantError(APIResponse):
    def __init__(self):
        self.status = "UNKNOWN_TENANT_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class CreateOrUpdateThirdPartyConfigBoxyError(APIResponse):
    def __init__(self, message: str):
        self.status = "BOXY_ERROR"
        self.message = message

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "message": self.message}


async def handle_create_or_update_third_party_config(
    _: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    CreateOrUpdateThirdPartyConfigOkResult,
    CreateOrUpdateThirdPartyConfigUnknownTenantError,
    CreateOrUpdateThirdPartyConfigBoxyError,
]:
    request_body = await api_options.request.json()
    if request_body is None:
        raise BadInputError("Request body is required")
    provider_config = request_body.get("providerConfig")

    tenant_res = await get_tenant(tenant_id, user_context)

    if tenant_res is None:
        return CreateOrUpdateThirdPartyConfigUnknownTenantError()

    if len(tenant_res.third_party_providers) == 0:
        mt_recipe = MultitenancyRecipe.get_instance()
        static_providers = mt_recipe.static_third_party_providers or []
        for provider in static_providers:
            if (
                provider.include_in_non_public_tenants_by_default
                or tenant_id == DEFAULT_TENANT_ID
            ):
                await create_or_update_third_party_config(
                    tenant_id,
                    ProviderConfig(third_party_id=provider.config.third_party_id),
                    None,
                    user_context,
                )
                await asyncio.sleep(0.5)  # 500ms delay

    if provider_config["thirdPartyId"].startswith("boxy-saml"):
        boxy_url = provider_config["clients"][0]["additionalConfig"]["boxyURL"]
        boxy_api_key = provider_config["clients"][0]["additionalConfig"]["boxyAPIKey"]
        provider_config["clients"][0]["additionalConfig"]["boxyAPIKey"] = None

        if boxy_api_key and provider_config["clients"][0]["additionalConfig"][
            "samlInputType"
        ] in [
            "xml",
            "url",
        ]:
            request_body_input: Dict[str, Any] = {
                "name": "",
                "label": "",
                "description": "",
                "tenant": provider_config["clients"][0]
                .get("additionalConfig", {})
                .get("boxyTenant")
                or f"{tenant_id}-{provider_config['thirdPartyId']}",
                "product": provider_config["clients"][0]["additionalConfig"].get(
                    "boxyProduct"
                )
                or "supertokens",
                "defaultRedirectUrl": provider_config["clients"][0]["additionalConfig"][
                    "redirectURLs"
                ][0],
                "forceAuthn": False,
                "encodedRawMetadata": encode_base64(
                    provider_config["clients"][0]["additionalConfig"].get("samlXML", "")
                ),
                "redirectUrl": json.dumps(
                    provider_config["clients"][0]["additionalConfig"]["redirectURLs"]
                ),
                "metadataUrl": provider_config["clients"][0]["additionalConfig"].get(
                    "samlURL", ""
                ),
            }

            normalised_domain = NormalisedURLDomain(boxy_url)
            normalised_base_path = NormalisedURLPath(boxy_url)
            connections_path = NormalisedURLPath("/api/v1/saml/config")

            status, resp = await do_post_request(
                normalised_domain.get_as_string_dangerous()
                + normalised_base_path.append(
                    connections_path
                ).get_as_string_dangerous(),
                body_params=request_body_input,
                headers={"Authorization": f"Api-Key {boxy_api_key}"},
            )

            if status != 200:
                if status == 401:
                    return CreateOrUpdateThirdPartyConfigBoxyError("Invalid API Key")
                return CreateOrUpdateThirdPartyConfigBoxyError(
                    resp.get("message", "Unknown error")
                )

            provider_config["clients"][0]["clientId"] = resp["clientID"]
            provider_config["clients"][0]["clientSecret"] = resp["clientSecret"]

    third_party_res = await create_or_update_third_party_config(
        tenant_id, ProviderConfig.from_json(provider_config), None, user_context
    )

    return CreateOrUpdateThirdPartyConfigOkResult(third_party_res.created_new)
