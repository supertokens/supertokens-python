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

from typing import Any, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.multitenancy.asyncio import get_tenant
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.thirdparty import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderInput,
)
from supertokens_python.recipe.thirdparty.provider import CommonProviderConfig, Provider
from supertokens_python.recipe.thirdparty.providers.config_utils import (
    find_and_create_provider_instance,
    merge_providers_from_core_and_static,
)
from supertokens_python.recipe.thirdparty.providers.utils import do_get_request
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions


class ProviderConfigResponse(APIResponse):
    def __init__(
        self,
        provider_config: ProviderConfig,
        is_get_authorisation_redirect_url_overridden: bool,
        is_exchange_auth_code_for_oauth_tokens_overridden: bool,
        is_get_user_info_overridden: bool,
    ):
        self.provider_config = provider_config
        self.is_get_authorisation_redirect_url_overridden = (
            is_get_authorisation_redirect_url_overridden
        )
        self.is_exchange_auth_code_for_oauth_tokens_overridden = (
            is_exchange_auth_code_for_oauth_tokens_overridden
        )
        self.is_get_user_info_overridden = is_get_user_info_overridden

    def to_json(self) -> Dict[str, Any]:
        json_response = self.provider_config.to_json()
        json_response["isGetAuthorisationRedirectUrlOverridden"] = (
            self.is_get_authorisation_redirect_url_overridden
        )
        json_response["isExchangeAuthCodeForOAuthTokensOverridden"] = (
            self.is_exchange_auth_code_for_oauth_tokens_overridden
        )
        json_response["isGetUserInfoOverridden"] = self.is_get_user_info_overridden
        return {
            "status": "OK",
            "providerConfig": json_response,
        }


class GetThirdPartyConfigUnknownTenantError(APIResponse):
    def __init__(self):
        self.status: Literal["UNKNOWN_TENANT_ERROR"] = "UNKNOWN_TENANT_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


async def get_third_party_config(
    _: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[ProviderConfigResponse, GetThirdPartyConfigUnknownTenantError]:
    tenant_res = await get_tenant(tenant_id, user_context)

    if tenant_res is None:
        return GetThirdPartyConfigUnknownTenantError()

    third_party_id = options.request.get_query_param("thirdPartyId")

    if third_party_id is None:
        raise_bad_input_exception("Please provide thirdPartyId")

    providers_from_core = tenant_res.third_party_providers
    mt_recipe = MultitenancyRecipe.get_instance()
    static_providers = mt_recipe.static_third_party_providers or []

    additional_config: Optional[Dict[str, Any]] = None

    # filter out providers that is not matching thirdPartyId
    providers_from_core = [
        provider
        for provider in providers_from_core
        if provider.third_party_id == third_party_id
    ]

    # if none left, add one to this list so that it takes priority while merging
    if len(providers_from_core) == 0:
        providers_from_core.append(ProviderConfig(third_party_id=third_party_id))

    # At this point, providersFromCore.length === 1

    # query param may be passed if we are creating a new third party config, check and update accordingly

    if any(
        [
            third_party_id.startswith(tp_id)
            for tp_id in ["okta", "active-directory", "boxy-saml", "google-workspaces"]
        ]
    ):
        if third_party_id.startswith("okta"):
            okta_domain = options.request.get_query_param("oktaDomain")
            if okta_domain is not None:
                additional_config = {"oktaDomain": okta_domain}
        elif third_party_id.startswith("active-directory"):
            directory_id = options.request.get_query_param("directoryId")
            if directory_id is not None:
                additional_config = {"directoryId": directory_id}
        elif third_party_id.startswith("boxy-saml"):
            boxy_url = options.request.get_query_param("boxyUrl")
            boxy_api_key = options.request.get_query_param("boxyAPIKey")
            if boxy_url is not None:
                additional_config = {"boxyURL": boxy_url}
                if boxy_api_key is not None:
                    additional_config["boxyAPIKey"] = boxy_api_key
        elif third_party_id.startswith("google-workspaces"):
            hd = options.request.get_query_param("hd")
            if hd is not None:
                additional_config = {"hd": hd}

        if additional_config is not None:
            providers_from_core[0].oidc_discovery_endpoint = None
            providers_from_core[0].authorization_endpoint = None
            providers_from_core[0].token_endpoint = None
            providers_from_core[0].user_info_endpoint = None

            if providers_from_core[0].clients is not None:
                for existing_client in providers_from_core[0].clients:
                    existing_client.additional_config = {
                        **(existing_client.additional_config or {}),
                        **additional_config,
                    }

    # filter out other providers from static
    static_providers = [
        provider
        for provider in static_providers
        if provider.config.third_party_id == third_party_id
    ]

    if len(static_providers) == 0 and third_party_id == "apple":
        static_providers.append(
            ProviderInput(
                config=ProviderConfig(
                    third_party_id="apple",
                    clients=[
                        ProviderClientConfig(
                            client_id="nonguessable-temporary-client-id"
                        )
                    ],
                )
            )
        )

        additional_config = {
            "teamId": "",
            "keyId": "",
            "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
        }

    if len(static_providers) == 1:
        # modify additional config if query param is passed
        if additional_config is not None:
            # we set these to undefined so that these can be computed using the query param that was provided
            static_providers[0].config.oidc_discovery_endpoint = None
            static_providers[0].config.authorization_endpoint = None
            static_providers[0].config.token_endpoint = None
            static_providers[0].config.user_info_endpoint = None
            if static_providers[0].config.clients is not None:
                for existing_client in static_providers[0].config.clients:
                    existing_client.additional_config = {
                        **(existing_client.additional_config or {}),
                        **additional_config,
                    }

    merged_providers_from_core_and_static = merge_providers_from_core_and_static(
        providers_from_core, static_providers, True
    )

    if len(merged_providers_from_core_and_static) != 1:
        raise Exception("should never come here!")

    for merged_provider in merged_providers_from_core_and_static:
        if merged_provider.config.third_party_id == third_party_id:
            if (
                merged_provider.config.clients is None
                or len(merged_provider.config.clients) == 0
            ):
                merged_provider.config.clients = [
                    ProviderClientConfig(
                        client_id="nonguessable-temporary-client-id",
                        additional_config=additional_config,
                    )
                ]

    clients: List[ProviderClientConfig] = []
    common_provider_config: CommonProviderConfig = CommonProviderConfig(
        third_party_id=third_party_id
    )
    is_get_authorisation_redirect_url_overridden = False
    is_exchange_auth_code_for_oauth_tokens_overridden = False
    is_get_user_info_overridden = False

    for provider in merged_providers_from_core_and_static:
        if provider.config.third_party_id == third_party_id:
            found_correct_config = False

            for client in provider.config.clients or []:
                try:
                    provider_instance = await find_and_create_provider_instance(
                        merged_providers_from_core_and_static,
                        third_party_id,
                        client.client_type,
                        user_context,
                    )
                    assert provider_instance is not None
                    clients.append(
                        ProviderClientConfig(
                            client_id=provider_instance.config.client_id,
                            client_secret=provider_instance.config.client_secret,
                            scope=provider_instance.config.scope,
                            client_type=provider_instance.config.client_type,
                            additional_config=provider_instance.config.additional_config,
                            force_pkce=provider_instance.config.force_pkce,
                        )
                    )
                    # common_provider_config = CommonProviderConfig(
                    #     third_party_id=provider_instance.config.third_party_id,
                    #     name=provider_instance.config.name,
                    #     authorization_endpoint=provider_instance.config.authorization_endpoint,
                    #     authorization_endpoint_query_params=provider_instance.config.authorization_endpoint_query_params,
                    #     token_endpoint=provider_instance.config.token_endpoint,
                    #     token_endpoint_body_params=provider_instance.config.token_endpoint_body_params,
                    #     user_info_endpoint=provider_instance.config.user_info_endpoint,
                    #     user_info_endpoint_query_params=provider_instance.config.user_info_endpoint_query_params,
                    #     user_info_endpoint_headers=provider_instance.config.user_info_endpoint_headers,
                    #     jwks_uri=provider_instance.config.jwks_uri,
                    #     oidc_discovery_endpoint=provider_instance.config.oidc_discovery_endpoint,
                    #     user_info_map=provider_instance.config.user_info_map,
                    #     require_email=provider_instance.config.require_email,
                    #     validate_id_token_payload=provider_instance.config.validate_id_token_payload,
                    #     validate_access_token=provider_instance.config.validate_access_token,
                    #     generate_fake_email=provider_instance.config.generate_fake_email,
                    # )
                    common_provider_config = provider_instance.config

                    if provider.override is not None:
                        before_override = Provider(
                            config=provider_instance.config,
                            id=provider_instance.id,
                        )
                        after_override = provider.override(before_override)

                        if (
                            before_override.get_authorisation_redirect_url  # pylint: disable=W0143
                            != after_override.get_authorisation_redirect_url
                        ):
                            is_get_authorisation_redirect_url_overridden = True
                        if (
                            before_override.exchange_auth_code_for_oauth_tokens  # pylint: disable=W0143
                            != after_override.exchange_auth_code_for_oauth_tokens
                        ):
                            is_exchange_auth_code_for_oauth_tokens_overridden = True
                        if (
                            before_override.get_user_info  # pylint: disable=W0143
                            != after_override.get_user_info
                        ):
                            is_get_user_info_overridden = True

                    found_correct_config = True
                except Exception:
                    clients.append(client)

            if not found_correct_config:
                common_provider_config = provider.config

            break

    if additional_config is not None and "privateKey" in additional_config:
        additional_config["privateKey"] = ""

    temp_clients = [
        client
        for client in clients
        if client.client_id == "nonguessable-temporary-client-id"
    ]

    final_clients = [
        client
        for client in clients
        if client.client_id != "nonguessable-temporary-client-id"
    ]
    if len(final_clients) == 0:
        final_clients = [
            ProviderClientConfig(
                client_id="",
                client_secret="",
                client_type=temp_clients[0].client_type,
                scope=temp_clients[0].scope,
                force_pkce=temp_clients[0].force_pkce,
                additional_config=additional_config,
            )
        ]

    # fill in boxy info from boxy instance
    if third_party_id.startswith("boxy-saml"):
        boxy_api_key = options.request.get_query_param("boxyAPIKey")
        if boxy_api_key and final_clients[0].client_id:
            assert isinstance(final_clients[0].additional_config, dict)
            boxy_url = final_clients[0].additional_config["boxyURL"]
            normalised_domain = NormalisedURLDomain(boxy_url)
            normalised_base_path = NormalisedURLPath(boxy_url)
            connections_path = NormalisedURLPath("/api/v1/saml/config")

            resp = await do_get_request(
                normalised_domain.get_as_string_dangerous()
                + normalised_base_path.append(
                    connections_path
                ).get_as_string_dangerous(),
                {"clientID": final_clients[0].client_id},
                {"Authorization": f"Api-Key {boxy_api_key}"},
            )

            json_response = resp
            final_clients[0].additional_config.update(
                {
                    "redirectURLs": json_response["redirectUrl"],
                    "boxyTenant": json_response["tenant"],
                    "boxyProduct": json_response["product"],
                }
            )

    provider_config = ProviderConfig(
        third_party_id=third_party_id,
        clients=final_clients,
        authorization_endpoint=common_provider_config.authorization_endpoint,
        authorization_endpoint_query_params=common_provider_config.authorization_endpoint_query_params,
        token_endpoint=common_provider_config.token_endpoint,
        token_endpoint_body_params=common_provider_config.token_endpoint_body_params,
        user_info_endpoint=common_provider_config.user_info_endpoint,
        user_info_endpoint_query_params=common_provider_config.user_info_endpoint_query_params,
        user_info_endpoint_headers=common_provider_config.user_info_endpoint_headers,
        jwks_uri=common_provider_config.jwks_uri,
        oidc_discovery_endpoint=common_provider_config.oidc_discovery_endpoint,
        user_info_map=common_provider_config.user_info_map,
        require_email=common_provider_config.require_email,
        validate_id_token_payload=common_provider_config.validate_id_token_payload,
        validate_access_token=common_provider_config.validate_access_token,
        generate_fake_email=common_provider_config.generate_fake_email,
        name=common_provider_config.name,
    )

    return ProviderConfigResponse(
        provider_config=provider_config,
        is_get_authorisation_redirect_url_overridden=is_get_authorisation_redirect_url_overridden,
        is_exchange_auth_code_for_oauth_tokens_overridden=is_exchange_auth_code_for_oauth_tokens_overridden,
        is_get_user_info_overridden=is_get_user_info_overridden,
    )
