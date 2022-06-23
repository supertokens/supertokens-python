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
import json
import os

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from mysite.store import get_codes, get_url_with_token
from mysite.utils import custom_init
from supertokens_python.recipe.session import SessionContainer

mode = os.environ.get('APP_MODE', 'asgi')

if mode == 'asgi':
    from supertokens_python.recipe.session.framework.django.asyncio import \
        verify_session

    @verify_session()
    async def session_info(request: HttpRequest):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        return JsonResponse({
            'sessionHandle': session_.get_handle(),
            'userId': session_.get_user_id(),
            'jwtPayload': session_.get_access_token_payload(),
            'sessionData': await session_.get_session_data()
        })
else:
    from supertokens_python.recipe.session.framework.django.syncio import \
        verify_session

    @verify_session()
    def session_info(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        return JsonResponse({
            'sessionHandle': session_.get_handle(),
            'userId': session_.get_user_id(),
            'accessTokenPayload': session_.get_access_token_payload(),
            'sessionData': session_.sync_get_session_data()
        })


def ping(request: HttpRequest):
    return HttpResponse('success')


def token(request: HttpRequest):
    latest_url_with_token = get_url_with_token()
    return JsonResponse({
        'latestURLWithToken': latest_url_with_token
    })


def test_get_device(request: HttpRequest):
    pre_auth_session_id = request.GET.get('preAuthSessionId', None)
    if pre_auth_session_id is None:
        return HttpResponse('')
    codes = get_codes(pre_auth_session_id)
    return JsonResponse({
        'preAuthSessionId': pre_auth_session_id,
        'codes': codes
    })


def test_set_flow(request: HttpRequest):
    body = json.loads(request.body)
    contact_method = body['contactMethod']
    flow_type = body['flowType']
    custom_init(contact_method=contact_method, flow_type=flow_type)
    return HttpResponse('')


def before_each(request: HttpRequest):
    setattr(settings, "CODE_STORE", dict())
    return HttpResponse('')


def test_feature_flags(request: HttpRequest):
    return JsonResponse({
        'available': ['passwordless', 'thirdpartypasswordless', 'generalerror']
    })
