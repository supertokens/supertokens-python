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
import os

from dotenv import load_dotenv
from flask import Flask, make_response, jsonify, g
from flask_cors import CORS

from supertokens_python import init, get_all_cors_headers, SupertokensConfig, InputAppInfo
from supertokens_python.framework.flask.flask_middleware import Middleware
from supertokens_python.recipe import session, thirdpartyemailpassword, thirdparty, emailpassword
from supertokens_python.recipe.emailpassword.types import InputFormField
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.thirdpartyemailpassword import Github, Google, Facebook

load_dotenv()


def get_api_port():
    return '8083'


def get_website_port():
    return '3031'


def get_website_domain():
    return 'http://localhost:' + get_website_port()


os.environ.setdefault('SUPERTOKENS_ENV', 'testing')

latest_url_with_token = None


async def create_and_send_custom_email(_, url_with_token):
    global latest_url_with_token
    latest_url_with_token = url_with_token


async def validate_age(value):
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

init(
    supertokens_config=SupertokensConfig('http://localhost:9000'),
    app_info=InputAppInfo(
        app_name="SuperTokens Demo",
        api_domain="0.0.0.0:" + get_api_port(),
        website_domain=get_website_domain()
    ),
    framework='flask',
    recipe_list=[
        session.init(),
        emailpassword.init(
            sign_up_feature=emailpassword.InputSignUpFeature(form_fields),
            reset_password_using_token_feature=emailpassword.InputResetPasswordUsingTokenFeature(
                create_and_send_custom_email=create_and_send_custom_email
            ),
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=create_and_send_custom_email
            )
        ),
        thirdparty.init(
            sign_in_and_up_feature=thirdparty.SignInAndUpFeature([
                Google(
                    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')
                ), Facebook(
                    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),
                    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET')
                ), Github(
                    client_id=os.environ.get('GITHUB_CLIENT_ID'),
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET')
                )
            ])
        ),
        thirdpartyemailpassword.init(
            sign_up_feature=thirdpartyemailpassword.InputSignUpFeature(form_fields),
            providers=[
                Google(
                    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')
                ), Facebook(
                    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),
                    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET')
                ), Github(
                    client_id=os.environ.get('GITHUB_CLIENT_ID'),
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET')
                )
            ]
        )
    ],
    telemetry=False
)


def make_default_options_response():
    _response = make_response()
    _response.status_code = 204
    return _response


app = Flask(__name__, template_folder='templates')
app.make_default_options_response = make_default_options_response
Middleware(app)
CORS(
    app=app,
    supports_credentials=True,
    origins=get_website_domain(),
    allow_headers=['Content-Type'] + get_all_cors_headers()
)


@app.route('/ping', methods=['GET'])
def ping():
    return 'success'


@app.route('/sessionInfo', methods=['GET'])
@verify_session()
def get_session_info():
    session_ = g.supertokens
    return jsonify({
        'sessionHandle': session_.get_handle(),
        'userId': session_.get_user_id(),
        'accessTokenPayload': session_.get_access_token_payload(),
        'sessionData': session_.sync_get_session_data()
    })


@app.route('/token', methods=['GET'])
def get_token():
    global latest_url_with_token
    return jsonify({
        'latestURLWithToken': latest_url_with_token
    })


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path):
    return ''


@app.errorhandler(Exception)
def all_exception_handler(_: Exception):
    print('inside exception handler')
    return 'Error', 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(get_api_port()), threaded=True)
