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

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.thirdparty.provider import ProviderInput
from supertokens_python.recipe.thirdparty.providers.config_utils import (
    find_and_create_provider_instance,
    merge_providers_from_core_and_static,
)

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

from .interfaces import (
    ManuallyCreateOrUpdateUserOkResult,
    RecipeInterface,
    SignInUpOkResult,
)
from .types import RawUserInfoFromProvider, ThirdPartyInfo, User


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, providers: List[ProviderInput]):
        super().__init__()
        self.querier = querier
        self.providers = providers

    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        params = {"userId": user_id}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user"),
            params,
            user_context=user_context,
        )
        if "status" in response and response["status"] == "OK":
            return User(
                response["user"]["id"],
                response["user"]["email"],
                response["user"]["timeJoined"],
                response["user"]["tenantIds"],
                ThirdPartyInfo(
                    response["user"]["thirdParty"]["userId"],
                    response["user"]["thirdParty"]["id"],
                ),
            )
        return None

    async def get_users_by_email(
        self, email: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> List[User]:
        response = await self.querier.send_get_request(
            NormalisedURLPath(f"{tenant_id}/recipe/users/by-email"),
            {"email": email},
            user_context=user_context,
        )
        users: List[User] = []
        users_list: List[Dict[str, Any]] = (
            response["users"] if "users" in response else []
        )
        for user in users_list:
            users.append(
                User(
                    user["id"],
                    user["email"],
                    user["timeJoined"],
                    user["tenantIds"],
                    ThirdPartyInfo(
                        user["thirdParty"]["userId"], user["thirdParty"]["id"]
                    ),
                )
            )
        return users

    async def get_user_by_thirdparty_info(
        self,
        third_party_id: str,
        third_party_user_id: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[User, None]:
        params = {
            "thirdPartyId": third_party_id,
            "thirdPartyUserId": third_party_user_id,
        }
        response = await self.querier.send_get_request(
            NormalisedURLPath(f"{tenant_id}/recipe/user"),
            params,
            user_context=user_context,
        )
        if "status" in response and response["status"] == "OK":
            return User(
                response["user"]["id"],
                response["user"]["email"],
                response["user"]["timeJoined"],
                response["user"]["tenantIds"],
                ThirdPartyInfo(
                    response["user"]["thirdParty"]["userId"],
                    response["user"]["thirdParty"]["id"],
                ),
            )
        return None

    async def sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> SignInUpOkResult:
        data = {
            "thirdPartyId": third_party_id,
            "thirdPartyUserId": third_party_user_id,
            "email": {"id": email},
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup"),
            data,
            user_context=user_context,
        )
        return SignInUpOkResult(
            User(
                response["user"]["id"],
                response["user"]["email"],
                response["user"]["timeJoined"],
                response["user"]["tenantIds"],
                ThirdPartyInfo(
                    response["user"]["thirdParty"]["userId"],
                    response["user"]["thirdParty"]["id"],
                ),
            ),
            response["createdNewUser"],
            oauth_tokens,
            raw_user_info_from_provider,
        )

    async def manually_create_or_update_user(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> ManuallyCreateOrUpdateUserOkResult:
        data = {
            "thirdPartyId": third_party_id,
            "thirdPartyUserId": third_party_user_id,
            "email": {"id": email},
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup"),
            data,
            user_context=user_context,
        )
        return ManuallyCreateOrUpdateUserOkResult(
            User(
                response["user"]["id"],
                response["user"]["email"],
                response["user"]["timeJoined"],
                response["user"]["tenantIds"],
                ThirdPartyInfo(
                    response["user"]["thirdParty"]["userId"],
                    response["user"]["thirdParty"]["id"],
                ),
            ),
            response["createdNewUser"],
        )

    async def get_provider(
        self,
        third_party_id: str,
        client_type: Optional[str],
        tenant_id: str,
        user_context: Dict[str, Any],
    ):
        mt_recipe = MultitenancyRecipe.get_instance()
        tenant_config = await mt_recipe.recipe_implementation.get_tenant(
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if tenant_config is None:
            raise Exception("Tenant not found")

        merged_providers = merge_providers_from_core_and_static(
            provider_configs_from_core=tenant_config.third_party.providers,
            provider_inputs_from_static=self.providers,
        )

        provider = await find_and_create_provider_instance(
            merged_providers, third_party_id, client_type, user_context
        )

        return provider
