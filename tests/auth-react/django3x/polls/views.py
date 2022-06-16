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
from typing import Any, Dict, List, Union

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from mysite.settings import custom_init
from supertokens_python.recipe.emailpassword import InputFormField
from supertokens_python.recipe.emailpassword.types import User
from supertokens_python.recipe.passwordless import (
    CreateAndSendCustomEmailParameters,
    CreateAndSendCustomTextMessageParameters)
from supertokens_python.recipe.session import SessionContainer

mode = os.environ.get('APP_MODE', 'asgi')
if mode == 'asgi':
    from supertokens_python.recipe.session.framework.django.asyncio import \
        verify_session
else:
    from supertokens_python.recipe.session.framework.django.syncio import \
        verify_session


async def save_code_text(param: CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]):
    code_store: Union[None, Dict[str, List[Dict[str, Any]]]] = getattr(settings, "CODE_STORE", None)
    codes: Union[None, List[Dict[str, Any]]] = []
    if code_store is not None:
        codes = code_store.get(param.pre_auth_session_id)
    else:
        code_store = dict()
    if codes is None:
        codes = []
    codes.append({
        'urlWithLinkCode': param.url_with_link_code,
        'userInputCode': param.user_input_code
    })
    code_store[param.pre_auth_session_id] = codes
    setattr(settings, "CODE_STORE", code_store)


async def save_code_email(param: CreateAndSendCustomEmailParameters, _: Dict[str, Any]):
    code_store: Union[None, Dict[str, List[Dict[str, Any]]]] = getattr(settings, "CODE_STORE", None)
    codes: Union[None, List[Dict[str, Any]]] = []
    if code_store is not None:
        codes = code_store.get(param.pre_auth_session_id)
    else:
        code_store = dict()
    if codes is None:
        codes = []
    codes.append({
        'urlWithLinkCode': param.url_with_link_code,
        'userInputCode': param.user_input_code
    })
    code_store[param.pre_auth_session_id] = codes
    setattr(settings, "CODE_STORE", code_store)

os.environ.setdefault('SUPERTOKENS_ENV', 'testing')


async def create_and_send_custom_email(_: User, url_with_token: str, __: Dict[str, Any]) -> None:
    setattr(settings, "LATEST_URL_WITH_TOKEN", url_with_token)


async def validate_age(value: Any):
    try:
        if int(value) < 18:
            return "You must be over 18 to register"
    except Exception:
        pass

    return None

form_fields = [
    InputFormField('name'),
    InputFormField('age', validate=validate_age),
    InputFormField('country', optional=True)
]


if mode == 'asgi':
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
    latest_url_with_token = getattr(settings, "LATEST_URL_WITH_TOKEN", None)
    return JsonResponse({
        'latestURLWithToken': latest_url_with_token
    })


def test_get_device(request: HttpRequest):
    pre_auth_session_id = request.GET.get('preAuthSessionId', None)
    if pre_auth_session_id is None:
        return HttpResponse('')
    code_store = getattr(settings, "CODE_STORE", None)
    codes = []
    if code_store is not None:
        codes = code_store.get(pre_auth_session_id)
    if codes is None:
        codes = []
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
        'available': ['passwordless', 'thirdpartypasswordless']
    })
