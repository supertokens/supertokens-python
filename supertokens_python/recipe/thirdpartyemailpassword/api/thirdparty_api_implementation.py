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

from typing import Any, Dict, Union

from supertokens_python.recipe.thirdparty.interfaces import (
    APIInterface,
    APIOptions,
    SignInUpPostNoEmailGivenByProviderResponse,
    SignInUpPostOkResult,
)
from supertokens_python.recipe.thirdparty.provider import Provider, RedirectUriInfo
from supertokens_python.recipe.thirdparty.types import User
from supertokens_python.types import GeneralErrorResponse

from ..interfaces import APIInterface as ThirdPartyEmailPasswordAPIInterface
from ..interfaces import ThirdPartySignInUpPostOkResult


def get_interface_impl(
    api_implementation: ThirdPartyEmailPasswordAPIInterface,
) -> APIInterface:
    implementation = APIInterface()

    implementation.disable_authorisation_url_get = (
        api_implementation.disable_authorisation_url_get
    )
    implementation.disable_sign_in_up_post = (
        api_implementation.disable_thirdparty_sign_in_up_post
    )
    implementation.disable_apple_redirect_handler_post = (
        api_implementation.disable_apple_redirect_handler_post
    )

    implementation.authorisation_url_get = api_implementation.authorisation_url_get
    if not implementation.disable_sign_in_up_post:

        async def sign_in_up_post(
            provider: Provider,
            redirect_uri_info: Union[RedirectUriInfo, None],
            oauth_tokens: Union[Dict[str, Any], None],
            tenant_id: str,
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ) -> Union[
            SignInUpPostOkResult,
            SignInUpPostNoEmailGivenByProviderResponse,
            GeneralErrorResponse,
        ]:
            result = await api_implementation.thirdparty_sign_in_up_post(
                provider,
                redirect_uri_info,
                oauth_tokens,
                tenant_id,
                api_options,
                user_context,
            )
            if isinstance(result, ThirdPartySignInUpPostOkResult):
                if result.user.third_party_info is None:
                    raise Exception("Third Party Info cannot be None")
                return SignInUpPostOkResult(
                    User(
                        result.user.user_id,
                        result.user.email,
                        result.user.time_joined,
                        result.user.tenant_ids,
                        result.user.third_party_info,
                    ),
                    result.created_new_user,
                    result.session,
                    result.oauth_tokens,
                    result.raw_user_info_from_provider,
                )
            return result

        implementation.sign_in_up_post = sign_in_up_post
    implementation.apple_redirect_handler_post = (
        api_implementation.apple_redirect_handler_post
    )

    return implementation
