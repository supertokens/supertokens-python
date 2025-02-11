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

from typing import TYPE_CHECKING, Any, Dict, Optional

from supertokens_python.recipe.thirdparty.interfaces import SignInUpPostOkResult
from supertokens_python.recipe.thirdparty.provider import RedirectUriInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIInterface, APIOptions

from supertokens_python.exceptions import BadInputError, raise_bad_input_exception
from supertokens_python.utils import (
    get_backwards_compatible_user_info,
    get_normalised_should_try_linking_with_session_user_flag,
    send_200_response,
)


async def handle_sign_in_up_api(
    api_implementation: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    from supertokens_python.auth_utils import load_session_in_auth_api_if_needed

    if api_implementation.disable_sign_in_up_post:
        return None

    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON input")

    third_party_id = body.get("thirdPartyId")
    client_type = body.get("clientType")

    if third_party_id is None or not isinstance(third_party_id, str):
        raise_bad_input_exception("Please provide the thirdPartyId in request body")

    oauth_tokens = None
    redirect_uri_info = None
    if body.get("redirectURIInfo") is not None:
        if body.get("redirectURIInfo").get("redirectURIOnProviderDashboard") is None:
            raise_bad_input_exception(
                "Please provide the redirectURIOnProviderDashboard in request body"
            )
        redirect_uri_info = body.get("redirectURIInfo")
    elif body.get("oAuthTokens") is not None:
        oauth_tokens = body.get("oAuthTokens")
    else:
        raise_bad_input_exception(
            "Please provide one of redirectURIInfo or oAuthTokens in the request body"
        )

    provider_response = await api_options.recipe_implementation.get_provider(
        third_party_id=third_party_id,
        client_type=client_type,
        tenant_id=tenant_id,
        user_context=user_context,
    )

    if provider_response is None:
        raise BadInputError(
            f"the provider {third_party_id} could not be found in the configuration"
        )

    provider = provider_response

    redirect_uri_info_parsed: Optional[RedirectUriInfo] = None
    if redirect_uri_info is not None:
        redirect_uri_info_parsed = RedirectUriInfo(
            redirect_uri_on_provider_dashboard=redirect_uri_info.get(
                "redirectURIOnProviderDashboard"
            ),
            redirect_uri_query_params=redirect_uri_info.get("redirectURIQueryParams"),
            pkce_code_verifier=redirect_uri_info.get("pkceCodeVerifier"),
        )

    should_try_linking_with_session_user = (
        get_normalised_should_try_linking_with_session_user_flag(
            api_options.request, body
        )
    )

    session = await load_session_in_auth_api_if_needed(
        api_options.request, should_try_linking_with_session_user, user_context
    )

    if session is not None:
        tenant_id = session.get_tenant_id()

    result = await api_implementation.sign_in_up_post(
        provider=provider,
        redirect_uri_info=redirect_uri_info_parsed,
        oauth_tokens=oauth_tokens,
        tenant_id=tenant_id,
        api_options=api_options,
        user_context=user_context,
        session=session,
        should_try_linking_with_session_user=should_try_linking_with_session_user,
    )

    if isinstance(result, SignInUpPostOkResult):
        return send_200_response(
            {
                "status": "OK",
                **get_backwards_compatible_user_info(
                    req=api_options.request,
                    user_info=result.user,
                    session_container=result.session,
                    created_new_recipe_user=result.created_new_recipe_user,
                    user_context=user_context,
                ),
            },
            api_options.response,
        )

    return send_200_response(result.to_json(), api_options.response)
