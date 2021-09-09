"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.thirdparty.recipe import ThirdPartyRecipe
    from supertokens_python.thirdparty.provider import Provider
from supertokens_python.utils import find_first_occurrence_in_list
from supertokens_python.exceptions import raise_bad_input_exception
from urllib.parse import urlencode


async def handle_authorisation_url_api(recipe: ThirdPartyRecipe, request: BaseRequest, response: BaseResponse):
    third_party_id = request.get_query_param('thirdPartyId')

    if third_party_id is None:
        raise_bad_input_exception(recipe, 'Please provide the thirdPartyId as a GET param')

    provider: Provider = find_first_occurrence_in_list(lambda x: x.id == third_party_id, recipe.providers)
    if provider is None:
        raise_bad_input_exception(recipe, 'The third party provider ' + third_party_id + 'seems to not be configured '
                                                                                         'on the backend. Please '
                                                                                         'check your frontend and '
                                                                                         'backend configs.')

    authorisation_url_info = provider.get_authorisation_redirect_api_info()

    params = {}
    for key, value in authorisation_url_info.params.items():
        params[key] = value if not callable(value) else value(request)
    query_string = urlencode(params)

    url = authorisation_url_info.url + '?' + query_string

    response.set_content({
        'status': 'OK',
        'url': url
    })

    return response
