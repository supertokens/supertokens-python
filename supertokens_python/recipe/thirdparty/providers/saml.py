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
from __future__ import annotations

from typing import Any, Dict, Union

from ..provider import (
    AuthorisationRedirect,
    Provider,
    ProviderInput,
    RedirectUriInfo,
)
from ..types import RawUserInfoFromProvider, UserInfo, UserInfoEmail
from .custom import GenericProvider, NewProvider


class SAMLProviderImpl(GenericProvider):
    def __init__(self, provider_config: Any):
        super().__init__(provider_config)
        self.provider_type = "saml"

    async def get_authorisation_redirect_url(
        self,
        redirect_uri_on_provider_dashboard: str,
        user_context: Dict[str, Any],
    ) -> AuthorisationRedirect:
        from supertokens_python.supertokens import Supertokens

        st_instance = Supertokens.get_instance()
        app_info = st_instance.app_info

        # Build URL to the SAML recipe's login endpoint
        # The tenantId will be extracted from the redirect_uri_on_provider_dashboard
        # or we use the default path
        saml_login_url = (
            app_info.api_domain.get_as_string_dangerous()
            + app_info.api_base_path.get_as_string_dangerous()
            + "/saml/login"
        )

        from urllib.parse import urlencode

        query_params: Dict[str, str] = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri_on_provider_dashboard,
        }

        url = f"{saml_login_url}?{urlencode(query_params)}"

        return AuthorisationRedirect(url_with_query_params=url, pkce_code_verifier=None)

    async def exchange_auth_code_for_oauth_tokens(
        self, redirect_uri_info: RedirectUriInfo, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        raise Exception(
            "SAML providers do not support exchangeAuthCodeForOAuthTokens. "
            "The thirdparty sign-in-up flow handles SAML token extraction directly."
        )

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        from supertokens_python.recipe.saml.recipe import SAMLRecipe

        access_token = oauth_tokens.get("access_token", "")
        client_id = self.config.client_id

        # Use the SAML recipe to get user info
        saml_recipe = SAMLRecipe.get_instance()
        # tenant_id is passed through oauth_tokens by the sign_in_up_post handler
        tenant_id = oauth_tokens.get("_tenant_id", "public")

        result = await saml_recipe.recipe_implementation.get_user_info(
            tenant_id=tenant_id,
            access_token=access_token,
            client_id=client_id,
            user_context=user_context,
        )

        from supertokens_python.recipe.saml.types import GetUserInfoOkResult

        if isinstance(result, GetUserInfoOkResult):
            email_info: Union[UserInfoEmail, None] = None
            if result.email:
                email_info = UserInfoEmail(email=result.email, is_verified=True)

            raw_user_info = RawUserInfoFromProvider(
                from_id_token_payload=None,
                from_user_info_api=result.claims,
            )

            return UserInfo(
                third_party_user_id=result.sub,
                email=email_info,
                raw_user_info_from_provider=raw_user_info,
            )

        raise Exception("Failed to get user info from SAML provider")


def SAML(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if not input.config.name:
        input.config.name = "SAML"

    return NewProvider(input, SAMLProviderImpl)
