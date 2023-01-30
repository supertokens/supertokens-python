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

from typing import TYPE_CHECKING
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.multitenancy.exceptions import (
    RecipeDisabledForTenantError,
)
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions, APIInterface

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.utils import default_user_context, send_200_response


async def handle_sign_in_up_api(
    api_implementation: APIInterface, api_options: APIOptions
):
    if api_implementation.disable_sign_in_up_post:
        return None

    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON input")

    third_party_id = body.get("thirdPartyId")
    client_type = body.get("clientType")
    tenant_id = body.get("tenantId")

    if third_party_id is None or not isinstance(third_party_id, str):
        raise_bad_input_exception("Please provide the thirdPartyId in request body")

    redirect_uri_info = body.get("redirectURIInfo")
    oauth_tokens = body.get("oAuthTokens")

    if redirect_uri_info is not None:
        if redirect_uri_info.get("redirectURIOnProviderDashboard") is None:
            raise_bad_input_exception(
                "Please provide the redirectURIOnProviderDashboard in request body"
            )
    elif oauth_tokens is not None:
        pass  # Nothing to do here
    else:
        raise_bad_input_exception(
            "Please provide one of redirectURIInfo or oAuthTokens in the request body"
        )

    user_context = default_user_context(api_options.request)

    mt_recipe = MultitenancyRecipe.get_instance()
    tenant_id = await mt_recipe.recipe_implementation.get_tenant_id(
        tenant_id, user_context
    )

    provider_response = await api_options.recipe_implementation.get_provider(
        third_party_id=third_party_id,
        tenant_id=tenant_id,
        client_type=client_type,
        user_context=user_context,
    )

    if not provider_response.third_party_enabled:
        raise RecipeDisabledForTenantError(
            f"The third party recipe is disabled for {tenant_id if tenant_id is not None and tenant_id != DEFAULT_TENANT_ID else 'default tenant'}"
        )

    provider = provider_response.provider

    result = await api_implementation.sign_in_up_post(
        provider=provider,
        redirect_uri_info=redirect_uri_info,
        oauth_tokens=oauth_tokens,
        api_options=api_options,
        user_context=user_context,
    )
    return send_200_response(result.to_json(), api_options.response)
