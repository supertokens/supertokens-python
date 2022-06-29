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

from typing import TYPE_CHECKING, Union

from supertokens_python.recipe.thirdparty.utils import find_right_provider

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions, APIInterface
    from supertokens_python.recipe.thirdparty.provider import Provider

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.utils import default_user_context, send_200_response


async def handle_authorisation_url_api(
    api_implementation: APIInterface, api_options: APIOptions
):
    if api_implementation.disable_authorisation_url_get:
        return None
    third_party_id = api_options.request.get_query_param("thirdPartyId")

    if third_party_id is None:
        raise_bad_input_exception("Please provide the thirdPartyId as a GET param")

    provider: Union[None, Provider] = find_right_provider(
        api_options.providers, third_party_id, None
    )
    if provider is None:
        raise_bad_input_exception(
            "The third party provider "
            + third_party_id
            + " seems to be missing from the backend configs."
        )
    user_context = default_user_context(api_options.request)

    result = await api_implementation.authorisation_url_get(
        provider, api_options, user_context
    )
    return send_200_response(result.to_json(), api_options.response)
