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

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from supertokens_python.recipe.multitenancy.interfaces import (
    AssociateUserToTenantEmailAlreadyExistsError,
    AssociateUserToTenantOkResult,
    AssociateUserToTenantPhoneNumberAlreadyExistsError,
    AssociateUserToTenantThirdPartyUserAlreadyExistsError,
    AssociateUserToTenantUnknownUserIdError,
    DisassociateUserFromTenantOkResult,
)
from supertokens_python.types import RecipeUserId

from .interfaces import (
    AssociateUserToTenantNotAllowedError,
    CreateOrUpdateTenantOkResult,
    CreateOrUpdateThirdPartyConfigOkResult,
    DeleteTenantOkResult,
    DeleteThirdPartyConfigOkResult,
    ListAllTenantsOkResult,
    RecipeInterface,
    TenantConfig,
    TenantConfigCreateOrUpdate,
)

if TYPE_CHECKING:
    from supertokens_python.querier import Querier
    from supertokens_python.recipe.thirdparty.provider import ProviderConfig

    from .utils import MultitenancyConfig

from supertokens_python.querier import NormalisedURLPath

from .constants import DEFAULT_TENANT_ID


def parse_tenant_config(tenant: Dict[str, Any]) -> TenantConfig:
    from supertokens_python.recipe.thirdparty.provider import (
        ProviderClientConfig,
        ProviderConfig,
        UserFields,
        UserInfoMap,
    )

    providers: List[ProviderConfig] = []
    for p in tenant["thirdParty"]["providers"]:
        user_info_map: Optional[UserInfoMap] = None
        if "userInfoMap" in p:
            map_from_payload = p["userInfoMap"].get("fromIdTokenPayload", {})
            map_from_api = p["userInfoMap"].get("fromUserInfoAPI", {})
            user_info_map = UserInfoMap(
                UserFields(
                    map_from_payload.get("userId"),
                    map_from_payload.get("email"),
                    map_from_payload.get("emailVerified"),
                ),
                UserFields(
                    map_from_api.get("userId"),
                    map_from_api.get("email"),
                    map_from_api.get("emailVerified"),
                ),
            )

        providers.append(
            ProviderConfig(
                third_party_id=p["thirdPartyId"],
                name=p.get("name"),
                clients=[
                    ProviderClientConfig(
                        client_id=c["clientId"],
                        client_secret=c.get("clientSecret"),
                        client_type=c.get("clientType"),
                        scope=c.get("scope"),
                        force_pkce=c.get("forcePKCE", False),
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
                jwks_uri=p.get("jwksURI"),
                oidc_discovery_endpoint=p.get("oidcDiscoveryEndpoint"),
                user_info_map=user_info_map,
                require_email=p.get("requireEmail", True),
                validate_id_token_payload=None,
                generate_fake_email=None,
                validate_access_token=None,
            )
        )

    return TenantConfig(
        tenant_id=tenant["tenantId"],
        third_party_providers=providers,
        core_config=tenant["coreConfig"],
        first_factors=tenant.get("firstFactors"),
        required_secondary_factors=tenant.get("requiredSecondaryFactors"),
    )


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, config: MultitenancyConfig):
        super().__init__()
        self.querier = querier
        self.config = config

    async def get_tenant_id(
        self, tenant_id_from_frontend: str, user_context: Dict[str, Any]
    ) -> str:
        return tenant_id_from_frontend

    async def create_or_update_tenant(
        self,
        tenant_id: str,
        config: Optional[TenantConfigCreateOrUpdate],
        user_context: Dict[str, Any],
    ) -> CreateOrUpdateTenantOkResult:
        json_body: Dict[str, Any] = {
            "tenantId": tenant_id,
        }
        if config is not None:
            if not config.is_first_factors_unchanged():
                json_body["firstFactors"] = config.get_first_factors_for_update()
            if not config.is_required_secondary_factors_unchanged():
                json_body["requiredSecondaryFactors"] = (
                    config.get_required_secondary_factors_for_update()
                )
            json_body["coreConfig"] = config.core_config

        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/multitenancy/tenant/v2"),
            json_body,
            None,
            user_context=user_context,
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
            user_context=user_context,
        )
        return DeleteTenantOkResult(
            did_exist=response["didExist"],
        )

    async def get_tenant(
        self, tenant_id: Optional[str], user_context: Dict[str, Any]
    ) -> Optional[TenantConfig]:
        res = await self.querier.send_get_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/tenant/v2"
            ),
            None,
            user_context=user_context,
        )

        if res["status"] == "TENANT_NOT_FOUND_ERROR":
            return None

        tenant_config = parse_tenant_config(res)

        return tenant_config

    async def list_all_tenants(
        self, user_context: Dict[str, Any]
    ) -> ListAllTenantsOkResult:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/multitenancy/tenant/list/v2"),
            {},
            user_context=user_context,
        )

        tenant_items: List[TenantConfig] = []

        for tenant in response["tenants"]:
            config = parse_tenant_config(tenant)
            tenant_items.append(config)

        return ListAllTenantsOkResult(
            tenants=tenant_items,
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
            None,
            user_context=user_context,
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
            user_context=user_context,
        )

        return DeleteThirdPartyConfigOkResult(
            did_config_exist=response["didConfigExist"],
        )

    async def associate_user_to_tenant(
        self,
        tenant_id: Optional[str],
        recipe_user_id: RecipeUserId,
        user_context: Dict[str, Any],
    ) -> Union[
        AssociateUserToTenantOkResult,
        AssociateUserToTenantUnknownUserIdError,
        AssociateUserToTenantEmailAlreadyExistsError,
        AssociateUserToTenantPhoneNumberAlreadyExistsError,
        AssociateUserToTenantThirdPartyUserAlreadyExistsError,
        AssociateUserToTenantNotAllowedError,
    ]:
        response = await self.querier.send_post_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/tenant/user"
            ),
            {
                "recipeUserId": recipe_user_id.get_as_string(),
            },
            user_context=user_context,
        )

        if response["status"] == "OK":
            return AssociateUserToTenantOkResult(
                was_already_associated=response["wasAlreadyAssociated"],
            )
        if response["status"] == AssociateUserToTenantUnknownUserIdError.status:
            return AssociateUserToTenantUnknownUserIdError()
        if response["status"] == AssociateUserToTenantEmailAlreadyExistsError.status:
            return AssociateUserToTenantEmailAlreadyExistsError()
        if (
            response["status"]
            == AssociateUserToTenantPhoneNumberAlreadyExistsError.status
        ):
            return AssociateUserToTenantPhoneNumberAlreadyExistsError()
        if (
            response["status"]
            == AssociateUserToTenantThirdPartyUserAlreadyExistsError.status
        ):
            return AssociateUserToTenantThirdPartyUserAlreadyExistsError()
        if response["status"] == AssociateUserToTenantNotAllowedError.status:
            return AssociateUserToTenantNotAllowedError(response["reason"])

        raise Exception("Should never come here")

    async def disassociate_user_from_tenant(
        self,
        tenant_id: Optional[str],
        recipe_user_id: RecipeUserId,
        user_context: Dict[str, Any],
    ) -> DisassociateUserFromTenantOkResult:
        response = await self.querier.send_post_request(
            NormalisedURLPath(
                f"{tenant_id or DEFAULT_TENANT_ID}/recipe/multitenancy/tenant/user/remove"
            ),
            {
                "recipeUserId": recipe_user_id.get_as_string(),
            },
            user_context=user_context,
        )

        return DisassociateUserFromTenantOkResult(
            was_associated=response["wasAssociated"],
        )
