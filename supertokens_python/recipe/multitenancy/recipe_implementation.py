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

from typing import TYPE_CHECKING, Optional, Dict, Any, Union, List
from supertokens_python.recipe.multitenancy.interfaces import (
    AssociateUserToTenantOkResult,
    AssociateUserToTenantUnknownUserIdErrorResult,
    AssociateUserToTenantEmailAlreadyExistsErrorResult,
    AssociateUserToTenantPhoneNumberAlreadyExistsErrorResult,
    AssociateUserToTenantThirdPartyUserAlreadyExistsErrorResult,
    DisassociateUserFromTenantOkResult,
)

from .interfaces import (
    RecipeInterface,
    TenantConfig,
    CreateOrUpdateTenantOkResult,
    DeleteTenantOkResult,
    TenantConfigResponse,
    GetTenantOkResult,
    EmailPasswordConfig,
    PasswordlessConfig,
    ThirdPartyConfig,
    ListAllTenantsOkResult,
    CreateOrUpdateThirdPartyConfigOkResult,
    DeleteThirdPartyConfigOkResult,
)

if TYPE_CHECKING:
    from supertokens_python.querier import Querier
    from supertokens_python.recipe.thirdparty.interfaces import ProviderConfig
    from .utils import MultitenancyConfig

from supertokens_python.querier import NormalisedURLPath
from .constants import DEFAULT_TENANT_ID


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, config: MultitenancyConfig):
        super().__init__()
        self.querier = querier
        self.config = config

    async def get_tenant_id(
        self, tenant_id_from_frontend: Optional[str], user_context: Dict[str, Any]
    ) -> Optional[str]:
        return tenant_id_from_frontend

    async def create_or_update_tenant(
        self,
        tenant_id: Optional[str],
        config: TenantConfig,
        user_context: Dict[str, Any],
    ) -> CreateOrUpdateTenantOkResult:
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/multitenancy/tenant"),
            {
                "tenantId": tenant_id,
                **config.to_json(),
            },
        )
        return CreateOrUpdateTenantOkResult(
            created_new=response["createdNew"],
        )

    async def delete_tenant(
        self, tenant_id: str, user_context: Dict[str, Any]
    ) -> DeleteTenantOkResult:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/multitenancy/tenant/remove"),
            {"tenantId": tenant_id},
        )
        return DeleteTenantOkResult(
            did_exist=response["didExist"],
        )

    async def get_tenant(
        self, tenant_id: Optional[str], user_context: Dict[str, Any]
    ) -> GetTenantOkResult:
        from supertokens_python.recipe.thirdparty.provider import (
            ProviderConfig,
            ProviderClientConfig,
        )

        res = await self.querier.send_get_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/tenant"
            ),
        )

        providers: List[ProviderConfig] = []
        for p in res["thirdParty"]["providers"]:
            providers.append(
                ProviderConfig(
                    third_party_id=p["thirdPartyId"],
                    name=p["name"],
                    clients=[
                        ProviderClientConfig(
                            client_id=c["clientId"],
                            client_secret=c.get("clientSecret"),
                            client_type=c.get("clientType"),
                            scope=c.get("scope"),
                            force_pkce=c.get("forcePkce"),
                            additional_config=c.get("additionalConfig"),
                        )
                        for c in p["clients"]
                    ],
                    authorization_endpoint=p.get("authorizationEndpoint"),
                    authorization_endpoint_query_params=p.get(
                        "authorizationEndpointQueryParams"
                    ),
                    token_endpoint=p.get("tokenEndpoint"),
                    token_endpoint_body_params=p.get("tokenEndpointBodyParams"),
                    user_info_endpoint=p.get("userInfoEndpoint"),
                    user_info_endpoint_query_params=p.get("userInfoEndpointQueryParams"),
                    user_info_endpoint_headers=p.get("userInfoEndpointHeaders"),
                    jwks_uri=p.get("jwksUri"),
                    oidc_discovery_endpoint=p.get("oidcDiscoveryEndpoint"),
                    user_info_map=p.get("userInfoMap"),
                    require_email=p.get("requireEmail"),
                    validate_id_token_payload=p.get("validateIdTokenPayload"),
                    generate_fake_email=p.get("generateFakeEmail"),
                )
            )

        # /t1/recipe/multitenancy/tenant

        return GetTenantOkResult(
            emailpassword=EmailPasswordConfig(res["emailPassword"]["enabled"]),
            passwordless=PasswordlessConfig(res["passwordless"]["enabled"]),
            third_party=ThirdPartyConfig(
                res["thirdParty"]["enabled"],
                providers,
            ),
            core_config=res["coreConfig"],
        )

    async def list_all_tenants(
        self, user_context: Dict[str, Any]
    ) -> ListAllTenantsOkResult:
        from supertokens_python.recipe.thirdparty.provider import (
            ProviderConfig,
            ProviderClientConfig,
        )

        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/multitenancy/tenant/list"),
            {},
        )

        tenant_configs: List[TenantConfigResponse] = []

        for tenant in response["tenants"]:
            providers: List[ProviderConfig] = []
            for p in tenant["thirdParty"]["providers"]:
                providers.append(
                    ProviderConfig(
                        third_party_id=p["thirdPartyId"],
                        name=p["name"],
                        clients=[
                            ProviderClientConfig(
                                client_id=c["clientId"],
                                client_secret=c["clientSecret"],
                                client_type=c["clientType"],
                                scope=c["scope"],
                                force_pkce=c["forcePkce"],
                                additional_config=c["additionalConfig"],
                            )
                            for c in p["clients"]
                        ],
                        authorization_endpoint=p["authorizationEndpoint"],
                        authorization_endpoint_query_params=p[
                            "authorizationEndpointQueryParams"
                        ],
                        token_endpoint=p["tokenEndpoint"],
                        token_endpoint_body_params=p["tokenEndpointBodyParams"],
                        user_info_endpoint=p["userInfoEndpoint"],
                        user_info_endpoint_query_params=p[
                            "userInfoEndpointQueryParams"
                        ],
                        user_info_endpoint_headers=p["userInfoEndpointHeaders"],
                        jwks_uri=p["jwksUri"],
                        oidc_discovery_endpoint=p["oidcDiscoveryEndpoint"],
                        user_info_map=p["userInfoMap"],
                        require_email=p["requireEmail"],
                        validate_id_token_payload=p["validateIdTokenPayload"],
                        generate_fake_email=p["generateFakeEmail"],
                    )
                )

            tenant_configs.append(
                TenantConfigResponse(
                    emailpassword=EmailPasswordConfig(
                        tenant["emailPassword"]["enabled"]
                    ),
                    passwordless=PasswordlessConfig(tenant["passwordless"]["enabled"]),
                    third_party=ThirdPartyConfig(
                        tenant["thirdParty"]["enabled"],
                        providers,
                    ),
                    core_config=tenant["coreConfig"],
                )
            )

        return ListAllTenantsOkResult(
            tenants=tenant_configs,
        )

    async def create_or_update_third_party_config(
        self,
        tenant_id: Optional[str],
        config: ProviderConfig,
        skip_validation: Optional[bool],
        user_context: Dict[str, Any],
    ) -> CreateOrUpdateThirdPartyConfigOkResult:
        response = await self.querier.send_put_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/config/thirdparty"
            ),
            {
                "config": config.to_json(),
                "skipValidation": skip_validation is True,
            },
        )

        return CreateOrUpdateThirdPartyConfigOkResult(
            created_new=response["createdNew"],
        )

    async def delete_third_party_config(
        self,
        tenant_id: Optional[str],
        third_party_id: str,
        user_context: Dict[str, Any],
    ) -> DeleteThirdPartyConfigOkResult:
        response = await self.querier.send_post_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/config/thirdparty/remove"
            ),
            {
                "thirdPartyId": third_party_id,
            },
        )

        return DeleteThirdPartyConfigOkResult(
            did_config_exist=response["didConfigExist"],
        )

    async def associate_user_to_tenant(
        self, tenant_id: str | None, user_id: str, user_context: Dict[str, Any]
    ) -> Union[
        AssociateUserToTenantOkResult,
        AssociateUserToTenantUnknownUserIdErrorResult,
        AssociateUserToTenantEmailAlreadyExistsErrorResult,
        AssociateUserToTenantPhoneNumberAlreadyExistsErrorResult,
        AssociateUserToTenantThirdPartyUserAlreadyExistsErrorResult,
    ]:
        response = await self.querier.send_post_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/tenant/user"
            ),
            {
                "userId": user_id,
            },
        )

        return AssociateUserToTenantOkResult(
            was_already_associated=response["wasAlreadyAssociated"],
        )

    async def dissociate_user_from_tenant(
        self, tenant_id: str | None, user_id: str, user_context: Dict[str, Any]
    ) -> DisassociateUserFromTenantOkResult:
        response = await self.querier.send_post_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/tenant/user/remove"
            ),
            {
                "userId": user_id,
            },
        )

        return DisassociateUserFromTenantOkResult(
            was_associated=response["wasAssociated"],
        )
