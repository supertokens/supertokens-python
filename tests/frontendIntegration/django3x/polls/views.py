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
import json
import os
import sys
from functools import wraps

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render

from supertokens_python import init, Supertokens
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.framework.django import verify_session
from supertokens_python.recipe.session import revoke_all_sessions_for_user, create_new_session, get_session

module_dir = os.path.dirname(__file__)  # get current directory
file_path = os.path.join(module_dir, '../templates/index.html')
print(file_path)
index_file = open(file_path, "r")
file_contents = index_file.read()
index_file.close()

os.environ.setdefault('SUPERTOKENS_ENV', 'testing')


def custom_decorator_for_test():
    def session_verify_custom_test(f):
        @wraps(f)
        async def wrapped_function(request, *args, **kwargs):
            Test.increment_attempted_refresh()
            try:
                value = f(request, *args, **kwargs)
                if value is not None and value.status_code != 200:
                    return value
                if request.headers.get("rid") is None:
                    return HttpResponse(content='refresh failed')
                Test.increment_refresh()
                return HttpResponse(content='refresh success')
            except Exception as e:
                raise e

        return wrapped_function

    return session_verify_custom_test


def try_refresh_token(_):
    return HttpResponse(json.dumps({'error': 'try refresh token'}), content_type="application/json", status=401)


def unauthorised(_):
    return HttpResponse(json.dumps({'error': 'unauthorised'}), content_type="application/json", status=401)


class Test:
    no_of_times_refresh_called_during_test = 0
    no_of_times_get_session_called_during_test = 0
    no_of_times_refresh_attempted_during_test = 0

    @staticmethod
    def reset():
        Test.no_of_times_refresh_called_during_test = 0
        Test.no_of_times_get_session_called_during_test = 0
        Test.no_of_times_refresh_attempted_during_test = 0

    @staticmethod
    def increment_refresh():
        Test.no_of_times_refresh_called_during_test = Test.no_of_times_refresh_called_during_test + 1

    @staticmethod
    def increment_attempted_refresh():
        Test.no_of_times_refresh_attempted_during_test = Test.no_of_times_refresh_attempted_during_test + 1

    @staticmethod
    def increment_get_session():
        Test.no_of_times_get_session_called_during_test = Test.no_of_times_get_session_called_during_test + 1

    @staticmethod
    def get_session_called_count():
        return Test.no_of_times_get_session_called_during_test

    @staticmethod
    def get_refresh_called_count():
        return Test.no_of_times_refresh_called_during_test

    @staticmethod
    def get_refresh_attempted_count():
        return Test.no_of_times_refresh_attempted_during_test


async def unauthorised_f(error, req, res):
    res.set_status_code(401)
    res.set_content({})


def apis_override_session(param):
    param.disable_refresh_post = True
    return param


def get_app_port():
    argvv = sys.argv
    for i in range(0, len(argvv)):
        if argvv[i] == '--port':
            return argvv[i + 1]

    return '8080'


def config(enable_anti_csrf: bool):
    return {
        'supertokens': {
            'connection_uri': "http://localhost:9000",
        },
        'framework': 'django',
        'app_info': {
            'app_name': "SuperTokens",
            'api_domain': "0.0.0.0:" + get_app_port(),
            'website_domain': "http://localhost.org:8080",
        },
        'recipe_list': [
            session.init({
                "error_handlers":
                    {
                        "on_unauthorised": unauthorised_f
                    },
                "anti_csrf": "VIA_TOKEN" if enable_anti_csrf else "NONE",
                "override": {
                    'apis': apis_override_session
                }
            })],
        'telemetry': False
    }


init(config(True))


async def send_file(request):
    return render(request, file_path)


async def send_options_api_response():
    return HttpResponse('')


async def login(request):
    if request.method == 'POST':
        user_id = json.loads(request.body)['userId']

        await create_new_session(request, user_id)
        return HttpResponse(user_id)
    else:
        return send_options_api_response()


async def before_each(request):
    if request.method == 'POST':
        Test.reset()
        return HttpResponse('')
    else:
        return send_options_api_response()


async def test_config(request):
    if request.method == 'POST':
        return HttpResponse('')
    else:
        return send_options_api_response()


async def multiple_interceptors(request):
    if request.method == 'POST':
        result_bool = 'success' if 'interceptorheader2' in request.headers \
                                   and 'interceptorheader1' in request.headers else 'failure'
        return HttpResponse(result_bool)
    else:
        return send_options_api_response()


@verify_session()
async def get_info(request):
    if request.method == 'GET':
        Test.increment_get_session()
        session = verify_session()(request).state
        resp = HttpResponse(session.get_user_id())
        resp['Cache-Control'] = 'no-cache, private'
        return resp
    else:
        return send_options_api_response()


@verify_session()
async def update_jwt(request):
    if request.method == 'GET':
        Test.increment_get_session()
        session = verify_session()(request).state
        resp = JsonResponse(session.get_jwt_payload())
        resp['Cache-Control'] = 'no-cache, private'
        return resp
    else:
        if request.method == 'POST':
            session = await verify_session()(request).state
            await session.update_jwt_payload(json.loads(request.body))
            Test.increment_get_session()
            resp = JsonResponse(session.get_jwt_payload())
            resp['Cache-Control'] = 'no-cache, private'
            return resp

    # options request
    return send_options_api_response()


async def testing(request):
    if request.method in ['GET', 'PUT', 'POST', 'DELETE']:
        if 'testing' in request.headers:
            resp = HttpResponse('success')
            resp['testing'] = request.headers['testing']
            return resp
        return HttpResponse("success")

    # options
    return send_options_api_response()


@verify_session()
async def logout(request):
    if request.method == 'POST':
        session = await verify_session()(request).state
        # session.revoke_session()
        await session.revoke_session()
        # revoke_session(session.get_handle())
        return HttpResponse('success')
    return send_options_api_response()


@verify_session()
async def revoke_all(request):
    if request.method:
        session = await get_session(request)
        await revoke_all_sessions_for_user(session.get_user_id())
        return HttpResponse('success')
    else:
        return send_options_api_response()


async def refresh_attempted_time(request):
    if request.method == 'GET':
        return HttpResponse(Test.get_refresh_attempted_count())
    else:
        return send_options_api_response()


@custom_decorator_for_test()
@verify_session()
def refresh(request):
    return


async def set_anti_csrf(request):
    data = json.loads(request.body)
    if "enableAntiCsrf" not in data:
        enable_csrf = True
    else:
        enable_csrf = data["enableAntiCsrf"]
    if enable_csrf is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        init(config(enable_csrf))
    return HttpResponse('success')


async def refresh_called_time(request):
    if request.method == 'GET':
        return HttpResponse(Test.get_refresh_called_count())
    else:
        return send_options_api_response()


async def get_session_called_time(request):
    if request.method == 'GET':
        return HttpResponse(str(Test.get_session_called_count()))
    else:
        return send_options_api_response()


async def ping(request):
    if request.method == 'GET':
        return HttpResponse('success')
    else:
        return send_options_api_response()


async def test_header(request):
    if request.method == 'GET':
        success_info = request.headers.get('st-custom-header')
        return JsonResponse({'success': success_info})
    else:
        return send_options_api_response()


async def check_device_info(request):
    if request.method == 'GET':
        sdk_name = request.headers.get('supertokens-sdk-name')
        sdk_version = request.headers.get('supertokens-sdk-version')
        return HttpResponse('true' if sdk_name == 'website' and isinstance(sdk_version, str) else 'false')
    else:
        return send_options_api_response()


async def check_rid(request):
    rid = request.headers.get('rid')
    return HttpResponse('fail' if rid is None else 'success')


async def check_allow_credentials(request):
    if request.method == 'GET':
        return JsonResponse(json.dumps('allow-credentials' in request.headers))
    else:
        return send_options_api_response()


async def test_error(request):
    if request.method == 'OPTIONS':
        return send_options_api_response()
    return HttpResponse('test error message', status=500)

# @app.exception_handler(405)
# def f_405(_, e):
#     return PlainTextResponse('', status_code=404)


# cors middleware added like this due to issue with add_middleware
# ref: https://github.com/tiangolo/fastapi/issues/1663
