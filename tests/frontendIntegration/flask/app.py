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
from functools import wraps
from typing import Literal, Union

from flask import Flask, request, make_response, Response, jsonify, render_template, g
from flask_cors import CORS

from supertokens_python import init, Supertokens, SupertokensConfig, InputAppInfo
from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.framework.flask.flask_middleware import Middleware
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionRecipe, InputErrorHandlers, Session
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session.syncio import revoke_all_sessions_for_user, create_new_session

last_set_enable_anti_csrf = True
last_set_enable_jwt = False

index_file = open("templates/index.html", "r")
file_contents = index_file.read()
index_file.close()

app = Flask(__name__, template_folder='templates')
Middleware(app)
CORS(app, supports_credentials=True)
os.environ.setdefault('SUPERTOKENS_ENV', 'testing')


def custom_decorator_for_test():
    def session_verify_custom_test(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            Test.increment_attempted_refresh()
            try:
                value = f(*args, **kwargs)
                if value is not None and value.status_code != 200:
                    return value
                if request.headers.get("rid") is None:
                    return 'refresh failed'
                Test.increment_refresh()
                return 'refresh success'
            except Exception as e:
                raise e

        return wrapped_function

    return session_verify_custom_test


def try_refresh_token(_):
    return jsonify({'error': 'try refresh token'}), 401


def unauthorised(_):
    return jsonify({'error': 'unauthorised'}), 401


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
    res.set_json_content({})
    return res


def apis_override_session(param):
    param.disable_refresh_post = True
    return param


def functions_override_session(param):
    original_create_new_session = param.create_new_session

    async def create_new_session_custom(_request, user_id, access_token_payload: Union[dict, None] = None,
                                        session_data: Union[dict, None] = None) -> Session:
        if access_token_payload is None:
            access_token_payload = {}
        access_token_payload = {
            **access_token_payload,
            'customClaim': 'customValue'
        }
        return await original_create_new_session(_request, user_id, access_token_payload, session_data)
    param.create_new_session = create_new_session_custom

    return param


def get_app_port():
    argvv = sys.argv
    for i in range(0, len(argvv)):
        if argvv[i] == '--port':
            return argvv[i + 1]

    return '8080'


def config(enable_anti_csrf: bool, enable_jwt: bool, jwt_property_name: Union[str, None]):
    anti_csrf: Literal['VIA_TOKEN', 'NONE'] = "NONE"
    if enable_anti_csrf:
        anti_csrf = "VIA_TOKEN"
    if enable_jwt:
        init(
            supertokens_config=SupertokensConfig('http://localhost:9000'),
            app_info=InputAppInfo(
                app_name="SuperTokens Python SDK",
                api_domain="0.0.0.0:" + get_app_port(),
                website_domain="http://localhost.org:8080"
            ),
            framework='flask',
            recipe_list=[session.init(
                error_handlers=InputErrorHandlers(
                    on_unauthorised=unauthorised_f
                ),
                anti_csrf=anti_csrf,
                override=session.InputOverrideConfig(
                    apis=apis_override_session,
                    functions=functions_override_session
                ),
                jwt=session.JWTConfig(enable_jwt, jwt_property_name)
            )],
            telemetry=False
        )
    else:
        init(
            supertokens_config=SupertokensConfig('http://localhost:9000'),
            app_info=InputAppInfo(
                app_name="SuperTokens Python SDK",
                api_domain="0.0.0.0:" + get_app_port(),
                website_domain="http://localhost.org:8080"
            ),
            framework='flask',
            recipe_list=[session.init(
                error_handlers=InputErrorHandlers(
                    on_unauthorised=unauthorised_f
                ),
                anti_csrf=anti_csrf,
                override=session.InputOverrideConfig(
                    apis=apis_override_session
                )
            )],
            telemetry=False
        )


config(True, False, None)


@app.route('/index.html', methods=['GET'])
def send_file():
    return render_template('index.html')


def send_options_api_response():
    return ''


@app.route("/login", methods=['OPTIONS'])
def login_options():
    return send_options_api_response()


@app.route('/login', methods=['POST'])
def login():
    user_id = request.get_json()['userId']
    _session = create_new_session(request, user_id)
    return _session.get_user_id()


@app.route("/beforeeach", methods=['OPTIONS'])
def before_each_options():
    return send_options_api_response()


@app.route('/beforeeach', methods=['POST'])
def before_each():
    Test.reset()
    return ''


@app.route("/testUserConfig", methods=['OPTIONS'])
def test_user_config_options():
    return send_options_api_response()


@app.route('/testUserConfig', methods=['POST'])
def test_config():
    return ''


@app.route("/multipleInterceptors", methods=['OPTIONS'])
def multiple_interceptors_options():
    return send_options_api_response()


@app.route('/multipleInterceptors', methods=['POST'])
def multiple_interceptors():
    result_bool = 'success' if 'interceptorheader2' in request.headers \
                               and 'interceptorheader1' in request.headers else 'failure'
    return str(result_bool)


@app.route("/", methods=['OPTIONS'])
def options():
    return send_options_api_response()


@app.route('/', methods=['GET'])
@verify_session()
def get_info():
    Test.increment_get_session()
    session = g.supertokens
    print(session.sync_get_session_data())
    print({
        'sessionHandle': session.get_handle(),
        'userId': session.get_user_id(),
        'jwtPayload': session.get_access_token_payload(),
        'sessionData': session.sync_get_session_data()
    })
    resp = make_response(session.get_user_id())
    resp.headers['Cache-Control'] = 'no-cache, private'
    return resp


@app.route("/update-jwt", methods=['OPTIONS'])
def update_options():
    return send_options_api_response()


@app.route('/update-jwt', methods=['GET'])
@verify_session()
# @supertokens_middleware(True)
def update_jwt():
    Test.increment_get_session()
    _session = g.supertokens

    resp = make_response(_session.get_access_token_payload())
    resp.headers['Cache-Control'] = 'no-cache, private'
    return resp


@app.route('/update-jwt', methods=['POST'])
@verify_session()
# @supertokens_middleware()
def update_jwt_post():
    _session = g.supertokens
    sync(_session.update_access_token_payload(request.get_json()))
    Test.increment_get_session()
    resp = make_response(_session.get_access_token_payload())
    resp.headers['Cache-Control'] = 'no-cache, private'
    return resp


@app.route("/testing", methods=['OPTIONS'])
def testing_options():
    return send_options_api_response()


@app.route('/testing', methods=['GET'])
def testing():
    if 'testing' in request.headers:
        resp = make_response('success')
        resp.headers['testing'] = request.headers['testing']
        return resp
    return "success"


@app.route('/testing', methods=['PUT'])
def testing_put():
    if 'testing' in request.headers:
        resp = make_response('success')
        resp.headers['testing'] = request.headers['testing']
        return resp
    return "success"


@app.route('/testing', methods=['POST'])
def testing_post():
    if 'testing' in request.headers:
        resp = make_response('success')
        resp.headers['testing'] = request.headers['testing']
        return resp
    return "success"


@app.route('/testing', methods=['DELETE'])
def testing_delete():
    if 'testing' in request.headers:
        resp = make_response('success')
        resp.headers['testing'] = request.headers['testing']
        return resp
    return 'success'


@app.route("/logout", methods=['OPTIONS'])
def logout_options():
    return send_options_api_response()


@app.route('/logout', methods=['POST'])
@verify_session()
def logout():
    _session = g.supertokens

    _session.sync_revoke_session()
    return 'success'


@app.route("/revokeAll", methods=['OPTIONS'])
def revoke_all_options():
    return send_options_api_response()


@app.route('/revokeAll', methods=['POST'])
@verify_session()
async def revoke_all():
    session_ = g.supertokens
    revoke_all_sessions_for_user(session_.get_user_id())
    return 'success'


@app.route("/refresh", methods=['OPTIONS'])
def refresh_options():
    return send_options_api_response()


@app.route("/refreshAttemptedTime", methods=['GET'])
def refresh_attempted_time():
    return str(Test.get_refresh_attempted_count())


@app.route('/auth/session/refresh', methods=['POST'])
@custom_decorator_for_test()
@verify_session()
def refresh():
    return ''


@app.route('/setAntiCsrf', methods=['POST'])
def set_anti_csrf():
    global last_set_enable_anti_csrf
    json = request.get_json(silent=True)
    if "enableAntiCsrf" not in json:
        enable_csrf = True
    else:
        enable_csrf = json["enableAntiCsrf"]

    last_set_enable_anti_csrf = enable_csrf
    if enable_csrf is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        config(enable_csrf, False, None)
    return 'success', 200


@app.route('/setEnableJWT', methods=['POST'])
def set_enable_jwt():
    global last_set_enable_jwt
    global last_set_enable_anti_csrf
    json = request.get_json(silent=True)
    if "enableJWT" not in json:
        enable_jwt = False
    else:
        enable_jwt = json["enableJWT"]

    last_set_enable_jwt = enable_jwt
    if enable_jwt is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        config(last_set_enable_anti_csrf, enable_jwt, None)
    return 'success', 200


@app.route("/refreshCalledTime", methods=['OPTIONS'])
def refresh_called_time_options():
    return send_options_api_response()


@app.route("/refreshCalledTime", methods=['GET'])
def refresh_called_time():
    return str(Test.get_refresh_called_count())


@app.route("/getSessionCalledTime", methods=['OPTIONS'])
def get_session_called_time_options():
    return send_options_api_response()


@app.route("/getSessionCalledTime", methods=['GET'])
def get_session_called_time():
    return str(Test.get_session_called_count())


@app.route("/ping", methods=['OPTIONS'])
def ping_options():
    return send_options_api_response()


@app.route('/ping', methods=['GET'])
def ping():
    return 'success'


@app.route("/testHeader", methods=['OPTIONS'])
def test_header_options():
    return send_options_api_response()


@app.route('/testHeader', methods=['GET'])
def test_header():
    success_info = request.headers.get('st-custom-header')
    return {'success': success_info}


@app.route("/checkDeviceInfo", methods=['OPTIONS'])
def check_device_info_options():
    return send_options_api_response()


@app.route('/checkDeviceInfo', methods=['GET'])
def check_device_info():
    sdk_name = request.headers.get('supertokens-sdk-name')
    sdk_version = request.headers.get('supertokens-sdk-version')
    return 'true' if sdk_name == 'website' and isinstance(
        sdk_version, str) else 'false'


@app.route('/check-rid', methods=['GET'])
def check_rid():
    rid = request.headers.get('rid')

    return 'fail' if rid is None else 'success'


@app.route('/featureFlags', methods=['GET'])
def feature_flags():
    global last_set_enable_jwt

    return jsonify({
        'sessionJwt': last_set_enable_jwt
    })


@app.route('/reinitialiseBackendConfig', methods=['POST'])
def reinitialize():
    global last_set_enable_jwt
    global last_set_enable_anti_csrf
    json = request.get_json(silent=True)
    if "jwtPropertyName" not in json:
        jwt_property_name = False
    else:
        jwt_property_name = json["jwtPropertyName"]

    Supertokens.reset()
    SessionRecipe.reset()
    config(last_set_enable_anti_csrf, last_set_enable_jwt, jwt_property_name)
    return '', 200


@app.route("/checkAllowCredentials", methods=['OPTIONS'])
def check_allow_credentials_options():
    return send_options_api_response()


@app.route('/checkAllowCredentials', methods=['GET'])
def check_allow_credentials():
    return jsonify(json.dumps('allow-credentials' in request.headers))


@app.route('/testError', methods=['GET', 'OPTIONS'])
def test_error():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    return Response('test error message', status=500)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(get_app_port()), threaded=True)
