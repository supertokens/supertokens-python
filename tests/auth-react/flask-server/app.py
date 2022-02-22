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
from typing import Any, Dict, List, Union

from dotenv import load_dotenv
from flask import Flask, g, jsonify, make_response, request
from flask_cors import CORS
from httpx import AsyncClient
from supertokens_python import (InputAppInfo, Supertokens, SupertokensConfig,
                                get_all_cors_headers, init)
from supertokens_python.framework.flask.flask_middleware import Middleware
from supertokens_python.recipe import (emailpassword, passwordless, session,
                                       thirdparty, thirdpartyemailpassword)
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.types import InputFormField, User
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.jwt import JWTRecipe
from supertokens_python.recipe.passwordless import (
    ContactEmailOnlyConfig, ContactEmailOrPhoneConfig, ContactPhoneOnlyConfig,
    CreateAndSendCustomEmailParameters,
    CreateAndSendCustomTextMessageParameters, PasswordlessRecipe)
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdparty.types import (
    AccessTokenAPI, AuthorisationRedirectAPI, UserInfo, UserInfoEmail)
from supertokens_python.recipe.thirdpartyemailpassword import (
    Facebook, Github, Google, ThirdPartyEmailPasswordRecipe)

from typing_extensions import Literal

load_dotenv()


def get_api_port():
    return '8083'


def get_website_port():
    return '3031'


def get_website_domain():
    return 'http://localhost:' + get_website_port()


os.environ.setdefault('SUPERTOKENS_ENV', 'testing')

latest_url_with_token = None

code_store: Dict[str, List[Dict[str, Any]]] = {}


async def save_code_email(param: CreateAndSendCustomEmailParameters, _: Dict[str, Any]):
    codes = code_store.get(param.pre_auth_session_id)
    if codes is None:
        codes = []
    codes.append({
        'urlWithLinkCode': param.url_with_link_code,
        'userInputCode': param.user_input_code
    })
    code_store[param.pre_auth_session_id] = codes


async def save_code_text(param: CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]):
    codes = code_store.get(param.pre_auth_session_id)
    if codes is None:
        codes = []
    codes.append({
        'urlWithLinkCode': param.url_with_link_code,
        'userInputCode': param.user_input_code
    })
    code_store[param.pre_auth_session_id] = codes


async def create_and_send_custom_email(_: User, url_with_token: str, __: Dict[str, Any]) -> None:
    global latest_url_with_token
    latest_url_with_token = url_with_token


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


class CustomAuth0Provider(Provider):
    def __init__(self, client_id: str, client_secret: str, domain: str):
        super().__init__('auth0', client_id, False)
        self.domain = domain
        self.client_secret = client_secret
        self.authorisation_redirect_url = "https://" + self.domain + "/authorize"
        self.access_token_api_url = "https://" + self.domain + "/oauth/token"

    async def get_profile_info(self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]) -> UserInfo:
        access_token: str = auth_code_response['access_token']
        headers = {
            'Authorization': 'Bearer ' + access_token,
        }
        async with AsyncClient() as client:
            response = await client.get(url="https://" + self.domain + "/userinfo", headers=headers)
            user_info = response.json()

            return UserInfo(user_info['sub'], UserInfoEmail(
                user_info['name'], True))

    def get_authorisation_redirect_api_info(self, user_context: Dict[str, Any]) -> AuthorisationRedirectAPI:
        params: Dict[str, Any] = {
            'scope': 'openid profile',
            'response_type': 'code',
            'client_id': self.client_id,
        }
        return AuthorisationRedirectAPI(
            self.authorisation_redirect_url, params)

    def get_access_token_api_info(
            self, redirect_uri: str, auth_code_from_request: str, user_context: Dict[str, Any]) -> AccessTokenAPI:
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': auth_code_from_request,
            'redirect_uri': redirect_uri
        }
        return AccessTokenAPI(self.access_token_api_url, params)

    def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]:
        return None


def custom_init(contact_method: Union[None, Literal['PHONE', 'EMAIL', 'EMAIL_OR_PHONE']] = None,
                flow_type: Union[None, Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']] = None):
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
                    create_and_send_custom_text_message=save_code_text
                ),
                flow_type=flow_type
            )
        elif contact_method == 'EMAIL':
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOnlyConfig(
                    create_and_send_custom_email=save_code_email
                ),
                flow_type=flow_type
            )
        else:
            passwordless_init = passwordless.init(
                contact_config=ContactEmailOrPhoneConfig(
                    create_and_send_custom_email=save_code_email,
                    create_and_send_custom_text_message=save_code_text
                ),
                flow_type=flow_type
            )
    else:
        passwordless_init = passwordless.init(
            contact_config=ContactPhoneOnlyConfig(
                create_and_send_custom_text_message=save_code_text
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
            sign_in_and_up_feature=thirdparty.SignInAndUpFeature([  # type: ignore
                Google(
                    client_id=os.environ.get('GOOGLE_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')  # type: ignore
                ), Facebook(
                    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET')  # type: ignore
                ), Github(
                    client_id=os.environ.get('GITHUB_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET')  # type: ignore
                ), CustomAuth0Provider(
                    client_id=os.environ.get('AUTH0_CLIENT_ID'),  # type: ignore
                    domain=os.environ.get('AUTH0_DOMAIN'),  # type: ignore
                    client_secret=os.environ.get('AUTH0_CLIENT_SECRET')  # type: ignore
                )
            ])
        ),
        thirdpartyemailpassword.init(
            sign_up_feature=thirdpartyemailpassword.InputSignUpFeature(
                form_fields),
            providers=[
                Google(
                    client_id=os.environ.get('GOOGLE_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')  # type: ignore
                ), Facebook(
                    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET')  # type: ignore
                ), Github(
                    client_id=os.environ.get('GITHUB_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET')  # type: ignore
                ), CustomAuth0Provider(
                    client_id=os.environ.get('AUTH0_CLIENT_ID'),  # type: ignore
                    domain=os.environ.get('AUTH0_DOMAIN'),  # type: ignore
                    client_secret=os.environ.get('AUTH0_CLIENT_SECRET')  # type: ignore
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


@app.route('/ping', methods=['GET'])  # type: ignore
def ping():
    return 'success'


@app.route('/sessionInfo', methods=['GET'])  # type: ignore
@verify_session()
def get_session_info():
    session_ = g.supertokens
    return jsonify({
        'sessionHandle': session_.get_handle(),
        'userId': session_.get_user_id(),
        'accessTokenPayload': session_.get_access_token_payload(),
        'sessionData': session_.sync_get_session_data()
    })


@app.route('/token', methods=['GET'])  # type: ignore
def get_token():
    global latest_url_with_token
    return jsonify({
        'latestURLWithToken': latest_url_with_token
    })


@app.route("/beforeeach", methods=["POST"])  # type: ignore
def before_each():
    global code_store
    code_store = dict()
    return ''


@app.route('/test/setFlow', methods=["POST"])  # type: ignore
async def test_set_flow():
    body: Union[Any, None] = request.get_json()
    if body is None:
        raise Exception("Should never come here")
    contact_method = body['contactMethod']
    flow_type = body['flowType']
    custom_init(contact_method=contact_method, flow_type=flow_type)
    return ''


@app.get("/test/getDevice")  # type: ignore
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


@app.get("/test/featureFlags")  # type: ignore
def test_feature_flags():
    available = ['passwordless']
    return jsonify({'available': available})


@app.route("/", defaults={"path": ""})  # type: ignore
@app.route("/<path:path>")  # type: ignore
def index(_: str):
    return ''


@app.errorhandler(Exception)  # type: ignore
def all_exception_handler(e: Exception):
    return 'Error', 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(get_api_port()), threaded=True)
