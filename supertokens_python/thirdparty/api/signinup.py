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
from supertokens_python.thirdparty.exceptions import raise_no_email_given_by_provider_exception
from supertokens_python.utils import find_first_occurrence_in_list
from supertokens_python.exceptions import raise_general_exception, raise_bad_input_exception
from supertokens_python.session import create_new_session
from httpx import AsyncClient


async def handle_sign_in_up_api(recipe: ThirdPartyRecipe, request: BaseRequest, response: BaseResponse):
    body = await request.json()

    if 'thirdPartyId' not in body or not isinstance(body['thirdPartyId'], str):
        raise_bad_input_exception(recipe, 'Please provide the thirdPartyId in request body')

    if 'code' not in body or not isinstance(body['code'], str):
        raise_bad_input_exception(recipe, 'Please provide the code in request body')

    if 'redirectURI' not in body or not isinstance(body['redirectURI'], str):
        raise_bad_input_exception(recipe, 'Please provide the redirectURI in request body')

    third_party_id = body['thirdPartyId']
    provider: Provider = find_first_occurrence_in_list(lambda x: x.id == third_party_id, recipe.providers)
    if provider is None:
        raise_bad_input_exception(recipe, 'The third party provider ' + third_party_id + ' seems to not be configured '
                                                                                         'on the backend. Please '
                                                                                         'check your frontend and '
                                                                                         'backend configs.')

    try:
        access_token_api_info = provider.get_access_token_api_info(body['redirectURI'], body['code'])
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        async with AsyncClient() as client:
            access_token_response = await client.post(access_token_api_info.url, data=access_token_api_info.params, headers=headers)
            access_token_response = access_token_response.json()
            user_info = await provider.get_profile_info(access_token_response)
    except Exception as e:
        raise_general_exception(recipe, e)

    email = user_info.email.id if user_info.email is not None else None
    email_verified = user_info.email.is_verified if user_info.email is not None else None
    if email is None or email_verified is None:
        raise_no_email_given_by_provider_exception('Provider ' + provider.id + 'returned no email info for the user.')
    signinup_response = await recipe.sign_in_up(provider.id, user_info.user_id, email, email_verified)
    user = signinup_response.user
    await recipe.config.sign_in_and_up_feature.handle_post_sign_up_in(user, access_token_response, signinup_response.is_new_user)

    action = 'signup' if signinup_response.is_new_user else 'signin'
    jwt_payload_promise = recipe.config.session_feature.set_jwt_payload(user, access_token_response, action)
    session_data_promise = recipe.config.session_feature.set_session_data(user, access_token_response, action)

    jwt_payload = {}
    session_data = {}
    try:
        jwt_payload = await jwt_payload_promise
        session_data = await session_data_promise
    except Exception as e:
        raise_general_exception(recipe, e)

    await create_new_session(request, user.user_id, jwt_payload, session_data)
    response.set_content({
        'status': 'OK',
        'user': {
            'id': user.user_id,
            'email': user.email,
            'timeJoined': user.time_joined,
            'thirdParty': {
                'id': user.third_party_info.id,
                'userId': user.third_party_info.user_id
            }
        },
        'createdNewUser': signinup_response.is_new_user
    })

    return response
