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
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from supertokens_python.recipe.passwordless import (
    ContactEmailOnlyConfig, ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig, CreateAndSendCustomEmailParameters, PasswordlessRecipe,
    CreateAndSendCustomTextMessageParameters
)
import typing
from supertokens_python import init, SupertokensConfig, InputAppInfo, Supertokens
from supertokens_python.recipe import session, thirdpartyemailpassword, thirdparty, emailpassword, passwordless
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe, InputFormField
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.jwt import JWTRecipe
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.thirdpartyemailpassword import Github, Google, Facebook, ThirdPartyEmailPasswordRecipe
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
import json
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdparty.types import UserInfo, AccessTokenAPI, AuthorisationRedirectAPI, UserInfoEmail
from httpx import AsyncClient
mode = os.environ.get('APP_MODE', 'asgi')
if mode == 'asgi':
    from supertokens_python.recipe.session.framework.django.asyncio import verify_session
else:
    from supertokens_python.recipe.session.framework.django.syncio import verify_session
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal


class CustomAuth0Provider(Provider):
    def __init__(self, client_id: str, client_secret: str, domain: str):
        super().__init__('auth0', client_id, False)
        self.domain = domain
        self.client_secret = client_secret
        self.authorisation_redirect_url = "https://" + self.domain + "/authorize"
        self.access_token_api_url = "https://" + self.domain + "/oauth/token"

    async def get_profile_info(self, auth_code_response: any) -> UserInfo:
        access_token: str = auth_code_response['access_token']
        headers = {
            'Authorization': 'Bearer ' + access_token,
        }
        async with AsyncClient() as client:
            response = await client.get(url="https://" + self.domain + "/userinfo", headers=headers)
            user_info = response.json()

            return UserInfo(user_info['sub'], UserInfoEmail(
                user_info['name'], True))

    def get_authorisation_redirect_api_info(self) -> AuthorisationRedirectAPI:
        params = {
            'scope': 'openid profile',
            'response_type': 'code',
            'client_id': self.client_id,
        }
        return AuthorisationRedirectAPI(
            self.authorisation_redirect_url, params)

    def get_access_token_api_info(
            self, redirect_uri: str, auth_code_from_request: str) -> AccessTokenAPI:
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': auth_code_from_request,
            'redirect_uri': redirect_uri
        }
        return AccessTokenAPI(self.access_token_api_url, params)


async def save_code(param: typing.Union[CreateAndSendCustomEmailParameters, CreateAndSendCustomTextMessageParameters], _):
    code_store = getattr(settings, "CODE_STORE", None)
    codes = []
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


async def create_and_send_custom_email(_, url_with_token, __):
    setattr(settings, "LATEST_URL_WITH_TOKEN", url_with_token)


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


def get_api_port():
    return '8083'


def get_website_port():
    return '3031'


def get_website_domain():
    return 'http://localhost:' + get_website_port()


def custom_init(contact_method: Literal['PHONE', 'EMAIL', 'EMAIL_OR_PHONE'] = None,
                flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'] = None):
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
                ), CustomAuth0Provider(
                    client_id=os.environ.get('AUTH0_CLIENT_ID'),
                    domain=os.environ.get('AUTH0_DOMAIN'),
                    client_secret=os.environ.get('AUTH0_CLIENT_SECRET')
                )
            ])
        ),
        thirdpartyemailpassword.init(
            sign_up_feature=thirdpartyemailpassword.InputSignUpFeature(
                form_fields),
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
                ), CustomAuth0Provider(
                    client_id=os.environ.get('AUTH0_CLIENT_ID'),
                    domain=os.environ.get('AUTH0_DOMAIN'),
                    client_secret=os.environ.get('AUTH0_CLIENT_SECRET')
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
        framework='django',
        mode=os.environ.get('APP_MODE', 'asgi'),
        recipe_list=recipe_list,
        telemetry=False
    )


if mode == 'asgi':
    @verify_session()
    async def session_info(request):
        session_ = request.supertokens
        return JsonResponse({
            'sessionHandle': session_.get_handle(),
            'userId': session_.get_user_id(),
            'jwtPayload': session_.get_access_token_payload(),
            'sessionData': await session_.get_session_data()
        })
else:
    @verify_session()
    def session_info(request):
        session_ = request.supertokens
        return JsonResponse({
            'sessionHandle': session_.get_handle(),
            'userId': session_.get_user_id(),
            'accessTokenPayload': session_.get_access_token_payload(),
            'sessionData': session_.sync_get_session_data()
        })


def ping(request):
    return HttpResponse('success')


def token(request):
    latest_url_with_token = getattr(settings, "LATEST_URL_WITH_TOKEN", None)
    return JsonResponse({
        'latestURLWithToken': latest_url_with_token
    })


def test_get_device(request):
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


def test_set_flow(request):
    body = json.loads(request.body)
    contact_method = body['contactMethod']
    flow_type = body['flowType']
    custom_init(contact_method=contact_method, flow_type=flow_type)
    return HttpResponse('')


def before_each(request):
    setattr(settings, "CODE_STORE", dict())
    return HttpResponse('')


def test_feature_flags(request):
    return JsonResponse({
        'available': ['passwordless']
    })
