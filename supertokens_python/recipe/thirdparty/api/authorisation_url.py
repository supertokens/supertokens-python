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

from typing import TYPE_CHECKING, Any, Dict
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.multitenancy.exceptions import (
    RecipeDisabledForTenantError,
)


if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions, APIInterface

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.utils import send_200_response


async def handle_authorisation_url_api(
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_authorisation_url_get:
        return None

    third_party_id = api_options.request.get_query_param("thirdPartyId")
    redirect_uri_on_provider_dashboard = api_options.request.get_query_param(
        "redirectURIOnProviderDashboard"
    )
    client_type = api_options.request.get_query_param("clientType")
    tenant_id = api_options.request.get_query_param("tenantId")

    if third_party_id is None:
        raise_bad_input_exception("Please provide the thirdPartyId as a GET param")

    if redirect_uri_on_provider_dashboard is None:
        raise_bad_input_exception(
            "Please provide the redirectURIOnProviderDashboard as a GET param"
        )

    mt_recipe = MultitenancyRecipe.get_instance()
    tenant_id = await mt_recipe.recipe_implementation.get_tenant_id(
        tenant_id if tenant_id is not None else DEFAULT_TENANT_ID, user_context
    )

    provider_response = await api_options.recipe_implementation.get_provider(
        third_party_id=third_party_id,
        client_type=client_type,
        tenant_id=tenant_id,
        user_context=user_context,
    )

    if not provider_response.third_party_enabled:
        raise RecipeDisabledForTenantError(
            f"The third party recipe is disabled for {tenant_id if tenant_id is not None and tenant_id != DEFAULT_TENANT_ID else 'default tenant'}"
        )

    provider = provider_response.provider
    result = await api_implementation.authorisation_url_get(
        provider=provider,
        redirect_uri_on_provider_dashboard=redirect_uri_on_provider_dashboard,
        api_options=api_options,
        user_context=user_context,
    )
    return send_200_response(result.to_json(), api_options.response)
