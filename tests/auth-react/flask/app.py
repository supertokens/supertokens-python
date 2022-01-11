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
import typing
from dotenv import load_dotenv
from flask import Flask, make_response, jsonify, g, request
from flask_cors import CORS

from supertokens_python import init, get_all_cors_headers, SupertokensConfig, InputAppInfo, Supertokens
from supertokens_python.framework.flask.flask_middleware import Middleware
from supertokens_python.recipe import session, thirdpartyemailpassword, thirdparty, emailpassword, passwordless
from supertokens_python.recipe.emailpassword.types import InputFormField
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.jwt import JWTRecipe
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.thirdpartyemailpassword import Github, Google, Facebook, ThirdPartyEmailPasswordRecipe
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.passwordless import (
    ContactEmailOnlyConfig, ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig, CreateAndSendCustomTextMessageParameters, PasswordlessRecipe,
    CreateAndSendCustomEmailParameters
)

load_dotenv()


def get_api_port():
    return '8083'


def get_website_port():
    return '3031'


def get_website_domain():
    return 'http://localhost:' + get_website_port()


os.environ.setdefault('SUPERTOKENS_ENV', 'testing')

latest_url_with_token = None

code_store = dict()


async def save_code(param: typing.Union[CreateAndSendCustomTextMessageParameters, CreateAndSendCustomEmailParameters]):
    codes = code_store.get(param.pre_auth_session_id)
    if codes is None:
        codes = []
    codes.append({
        'urlWithLinkCode': param.url_with_link_code,
        'userInputCode': param.user_input_code
    })
    code_store[param.pre_auth_session_id] = codes


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


def custom_init(contact_method: typing.Literal['PHONE', 'EMAIL', 'EMAIL_OR_PHONE'] = None,
                flow_type: typing.Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'] = None):
    PasswordlessRecipe.reset()
    JWTRecipe.reset()
    EmailVerificationRecipe.reset()
    SessionRecipe.reset()
    ThirdPartyRecipe.reset()
    EmailPasswordRecipe.reset()
    ThirdPartyEmailPasswordRecipe.reset()
    Supertokens.reset()

    if contact_method is not None and flow_type is not None:
        if contact_method == 'PHONE':
            passwordless_init = passwordless.init(
                contact_config=ContactPhoneOnlyConfig(
                    create_and_send_custom_text_message=save_code
                ),
                flow_type=flow_type
            )
        elif contact_method == 'EMAIL':
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOnlyConfig(
                    create_and_send_custom_email=save_code
                ),
                flow_type=flow_type
            )
        else:
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOrPhoneConfig(
                    create_and_send_custom_email=save_code,
                    create_and_send_custom_text_message=save_code
                ),
                flow_type=flow_type
            )
    else:
        passwordless_init = passwordless.init(
            contact_config=ContactPhoneOnlyConfig(
                create_and_send_custom_text_message=save_code
            ),
            flow_type='USER_INPUT_CODE_AND_MAGIC_LINK'
        )

    recipe_list = [
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
        ),
        passwordless_init
    ]

    init(
        supertokens_config=SupertokensConfig('http://localhost:9000'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="0.0.0.0:" + get_api_port(),
            website_domain=get_website_domain()
        ),
        framework='flask',
        recipe_list=recipe_list,
        telemetry=False
    )


custom_init()


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


@app.route("/beforeeach", methods=["POST"])
def before_each():
    global code_store
    code_store = dict()
    return ''


@app.route('/test/setFlow', methods=["POST"])
async def test_set_flow():
    body = request.get_json()
    contact_method = body['contactMethod']
    flow_type = body['flowType']
    custom_init(contact_method=contact_method, flow_type=flow_type)
    return ''


@app.get("/test/getDevice")
def test_get_device():
    global code_store
    pre_auth_session_id = request.args.get('preAuthSessionId')
    if pre_auth_session_id is None:
        return ''
    codes = code_store.get(pre_auth_session_id)
    return jsonify({
        'preAuthSessionId': pre_auth_session_id,
        'codes': codes
    })


@app.get("/test/featureFlags")
def test_feature_flags():
    available = ['passwordless']
    return jsonify({'available': available})


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
