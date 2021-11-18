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
import sys

import uvicorn
from starlette.requests import Request

from supertokens_python.framework.fastapi import Middleware
from supertokens_python.recipe.session.framework.fastapi import verify_session

from supertokens_python import init, get_all_cors_headers, Supertokens
from supertokens_python.recipe import session
from supertokens_python.recipe.session.asyncio import Session, revoke_all_sessions_for_user, create_new_session, SessionRecipe
from fastapi import FastAPI, Depends
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from starlette.exceptions import ExceptionMiddleware

index_file = open("templates/index.html", "r")
file_contents = index_file.read()
index_file.close()
app = FastAPI(debug=True)
app.add_middleware(Middleware)
os.environ.setdefault('SUPERTOKENS_ENV', 'testing')


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


async def unauthorised_f(_, __, res):
    res.set_status_code(401)
    res.set_json_content({})
    return res


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
        'framework': 'fastapi',
        'app_info': {
            'app_name': "SuperTokens Python SDK",
            'api_domain': "0.0.0.0:" + get_app_port(),
            'website_domain': "http://localhost.org:8080",
        },
        'recipe_list': [
            session.init({
                "error_handlers": {
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

app.add_middleware(ExceptionMiddleware, handlers=app.exception_handlers)


@app.get('/index.html')
def send_file():
    return HTMLResponse(content=file_contents)


def send_options_api_response():
    response = PlainTextResponse(content='', status_code=200)
    return response


@app.options("/login")
def login_options():
    return send_options_api_response()


@app.post('/login')
async def login(request: Request):
    user_id = (await request.json())['userId']
    await create_new_session(request, user_id)
    return PlainTextResponse(content=user_id)


@app.options("/beforeeach")
def before_each_options():
    return send_options_api_response()


@app.post('/beforeeach')
def before_each():
    Test.reset()
    return PlainTextResponse('')


@app.options("/testUserConfig")
def test_user_config_options():
    return send_options_api_response()


@app.post('/testUserConfig')
def test_config():
    return PlainTextResponse('')


@app.options("/multipleInterceptors")
def multiple_interceptors_options():
    return send_options_api_response()


@app.post('/multipleInterceptors')
def multiple_interceptors(request: Request):
    result_bool = 'success' if 'interceptorheader2' in request.headers \
                               and 'interceptorheader1' in request.headers else 'failure'
    return PlainTextResponse(result_bool)


@app.options("/")
def options():
    return send_options_api_response()


@app.get('/')
async def get_info(r_session: Session = Depends(verify_session())):
    Test.increment_get_session()
    return PlainTextResponse(content=r_session.get_user_id(), headers={
        'Cache-Control': 'no-cache, private'
    })


@app.options("/update-jwt")
def update_options():
    return send_options_api_response()


@app.get('/update-jwt')
async def update_jwt(sess: Session = Depends(verify_session())):
    Test.increment_get_session()
    return JSONResponse(content=sess.get_access_token_payload(), headers={
        'Cache-Control': 'no-cache, private'
    })


@app.post('/update-jwt')
async def update_jwt_post(request: Request, session: Session = Depends(verify_session())):
    await session.update_access_token_payload(await request.json())
    Test.increment_get_session()
    return JSONResponse(content=session.get_access_token_payload(), headers={
        'Cache-Control': 'no-cache, private'
    })


@app.options("/testing")
def testing_options():
    return send_options_api_response()


@app.get('/testing')
def testing(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={
                                 'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.put('/testing')
def testing_put(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={
                                 'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.post('/testing')
def testing_post(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={
                                 'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.delete('/testing')
def testing_delete(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={
                                 'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.options("/logout")
def logout_options():
    return send_options_api_response()


@app.post('/logout')
async def logout(session: Session = Depends(verify_session())):
    await session.revoke_session()
    return PlainTextResponse(content='success')


@app.options("/revokeAll")
def revoke_all_options():
    return send_options_api_response()


@app.post('/revokeAll')
async def revoke_all(session: Session = Depends(verify_session())):
    await revoke_all_sessions_for_user(session.get_user_id())
    return PlainTextResponse(content='success')


@app.options("/refresh")
def refresh_options():
    return send_options_api_response()


@app.get("/refreshAttemptedTime")
def refresh_attempted_time():
    return PlainTextResponse(content=str(
        Test.get_refresh_attempted_count()), status_code=200)


@app.post('/auth/session/refresh')
async def refresh(request: Request):
    Test.increment_attempted_refresh()
    try:
        await (verify_session()(request))
    except Exception as e:
        raise e

    if request.headers.get("rid") is None:
        return PlainTextResponse(content='refresh failed')
    Test.increment_refresh()
    return PlainTextResponse(content='refresh success')


@app.post('/setAntiCsrf')
async def set_anti_csrf(request: Request):
    json = await request.json()
    if "enableAntiCsrf" not in json:
        enable_csrf = True
    else:
        enable_csrf = json["enableAntiCsrf"]
    if enable_csrf is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        init(config(enable_csrf))
    return PlainTextResponse(content='success')


@app.options("/refreshCalledTime")
def refresh_called_time_options():
    return send_options_api_response()


@app.get("/refreshCalledTime")
def refresh_called_time():
    return PlainTextResponse(content=str(
        Test.get_refresh_called_count()), status_code=200)


@app.options("/getSessionCalledTime")
def get_session_called_time_options():
    return send_options_api_response()


@app.get("/getSessionCalledTime")
def get_session_called_time():
    return PlainTextResponse(content=str(
        Test.get_session_called_count()), status_code=200)


@app.options("/ping")
def ping_options():
    return send_options_api_response()


@app.get('/ping')
def ping():
    return PlainTextResponse(content='success')


@app.options("/testHeader")
def test_header_options():
    return send_options_api_response()


@app.get('/testHeader')
def test_header(request: Request):
    success_info = request.headers.get('st-custom-header')
    return JSONResponse({'success': success_info})


@app.options("/checkDeviceInfo")
def check_device_info_options():
    return send_options_api_response()


@app.get('/checkDeviceInfo')
def check_device_info(request: Request):
    sdk_name = request.headers.get('supertokens-sdk-name')
    sdk_version = request.headers.get('supertokens-sdk-version')
    return PlainTextResponse(
        'true' if sdk_name == 'website' and isinstance(sdk_version, str) else 'false')


@app.get('/check-rid')
def check_rid(request: Request):
    rid = request.headers.get('rid')

    return PlainTextResponse('fail' if rid is None else 'success')


@app.options("/checkAllowCredentials")
def check_allow_credentials_options():
    return send_options_api_response()


@app.get('/checkAllowCredentials')
def check_allow_credentials(request: Request):
    return PlainTextResponse(json.dumps(
        'allow-credentials' in request.headers), 200)


@app.route('/testError', methods=['GET', 'OPTIONS'])
def test_error(request: Request):
    if request.method == 'OPTIONS':
        return send_options_api_response()
    return PlainTextResponse('test error message', 500)


@app.exception_handler(405)
def f_405(_, e):
    return PlainTextResponse('', status_code=404)


# cors middleware added like this due to issue with add_middleware
# ref: https://github.com/tiangolo/fastapi/issues/1663


app = CORSMiddleware(
    app=app,
    allow_origins=[
        "http://localhost.org:8080"
    ],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
