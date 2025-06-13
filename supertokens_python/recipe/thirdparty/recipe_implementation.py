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

from supertokens_python.asyncio import get_user, list_users_by_account_info
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.thirdparty.provider import ProviderInput
from supertokens_python.recipe.thirdparty.providers.config_utils import (
    find_and_create_provider_instance,
    merge_providers_from_core_and_static,
)
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.base import AccountInfoInput

if TYPE_CHECKING:
    from supertokens_python.querier import Querier
    from supertokens_python.types.auth_utils import (
        LinkingToSessionUserFailedError,
    )

from .interfaces import (
    EmailChangeNotAllowedError,
    ManuallyCreateOrUpdateUserOkResult,
    RecipeInterface,
    SignInUpNotAllowed,
    SignInUpOkResult,
)
from .types import RawUserInfoFromProvider, ThirdPartyInfo


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, providers: List[ProviderInput]):
        super().__init__()
        self.querier = querier
        self.providers = providers

    async def sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        is_verified: bool,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[SignInUpOkResult, SignInUpNotAllowed, LinkingToSessionUserFailedError]:
        response = await self.manually_create_or_update_user(
            third_party_id=third_party_id,
            third_party_user_id=third_party_user_id,
            email=email,
            tenant_id=tenant_id,
            is_verified=is_verified,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            user_context=user_context,
        )

        if isinstance(response, EmailChangeNotAllowedError):
            return SignInUpNotAllowed(
                "Cannot sign in / up because new email cannot be applied to existing account. Please contact support. (ERR_CODE_005)"
                if response.reason
                == "Email already associated with another primary user."
                else "Cannot sign in / up because new email cannot be applied to existing account. Please contact support. (ERR_CODE_024)"
            )

        if isinstance(response, ManuallyCreateOrUpdateUserOkResult):
            return SignInUpOkResult(
                user=response.user,
                recipe_user_id=response.recipe_user_id,
                created_new_recipe_user=response.created_new_recipe_user,
                oauth_tokens=oauth_tokens,
                raw_user_info_from_provider=raw_user_info_from_provider,
            )

        return response

    async def manually_create_or_update_user(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        is_verified: bool,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        ManuallyCreateOrUpdateUserOkResult,
        LinkingToSessionUserFailedError,
        SignInUpNotAllowed,
        EmailChangeNotAllowedError,
    ]:
        from supertokens_python.auth_utils import (
            link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info,
        )

        account_linking = AccountLinkingRecipe.get_instance()
        users = await list_users_by_account_info(
            tenant_id,
            AccountInfoInput(
                third_party=ThirdPartyInfo(
                    third_party_id=third_party_id,
                    third_party_user_id=third_party_user_id,
                ),
            ),
            False,
            user_context,
        )

        user = users[0] if users else None
        if user is not None:
            is_email_change_allowed = await account_linking.is_email_change_allowed(
                user=user,
                is_verified=is_verified,
                new_email=email,
                session=session,
                user_context=user_context,
            )
            if not is_email_change_allowed.allowed:
                reason = (
                    "Email already associated with another primary user."
                    if is_email_change_allowed.reason == "PRIMARY_USER_CONFLICT"
                    else "New email cannot be applied to existing account because of account takeover risks."
                )
                return EmailChangeNotAllowedError(reason)

        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup"),
            {
                "thirdPartyId": third_party_id,
                "thirdPartyUserId": third_party_user_id,
                "email": {"id": email, "isVerified": is_verified},
            },
            user_context=user_context,
        )

        if response["status"] == "EMAIL_CHANGE_NOT_ALLOWED_ERROR":
            return EmailChangeNotAllowedError(response["reason"])

        # status is OK

        user = User.from_json(
            response["user"],
        )
        recipe_user_id = RecipeUserId(response["recipeUserId"])

        await account_linking.verify_email_for_recipe_user_if_linked_accounts_are_verified(
            user=user,
            recipe_user_id=recipe_user_id,
            user_context=user_context,
        )

        # Fetch updated user
        user = await get_user(recipe_user_id.get_as_string(), user_context)

        assert user is not None

        link_result = await link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
            tenant_id=tenant_id,
            input_user=user,
            recipe_user_id=recipe_user_id,
            session=session,
            user_context=user_context,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if link_result.status != "OK":
            return link_result

        return ManuallyCreateOrUpdateUserOkResult(
            user=link_result.user,
            recipe_user_id=recipe_user_id,
            created_new_recipe_user=response["createdNewUser"],
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
            provider_configs_from_core=tenant_config.third_party_providers,
            provider_inputs_from_static=self.providers,
            include_all_providers=tenant_id == DEFAULT_TENANT_ID,
        )

        provider = await find_and_create_provider_instance(
            merged_providers, third_party_id, client_type, user_context
        )

        return provider
