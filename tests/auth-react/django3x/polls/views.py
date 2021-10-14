"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

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
import os
from django.http import HttpResponse, JsonResponse
from supertokens_python.recipe.session.framework.django import verify_session
from django.conf import settings


module_dir = os.path.dirname(__file__)  # get current directory
file_path = os.path.join(module_dir, '../templates/index.html')
index_file = open(file_path, "r")
file_contents = index_file.read()
index_file.close()

os.environ.setdefault('SUPERTOKENS_ENV', 'testing')


@verify_session
async def session_info(request):
    session_ = request.state
    return JsonResponse({
        'sessionHandle': session_.get_handle(),
        'userId': session_.get_user_id(),
        'jwtPayload': session_.get_jwt_payload(),
        'sessionData': await session_.get_session_data()
    })


def ping(request):
    return HttpResponse('success')


def token(request):
    latest_url_with_token = getattr(settings, "LATEST_URL_WITH_TOKEN", None)
    return JsonResponse({
        'latestURLWithToken': latest_url_with_token
    })
