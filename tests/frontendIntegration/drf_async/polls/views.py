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
from django.http import HttpRequest
from supertokens_python.recipe.jwt.recipe import JWTRecipe
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.session.interfaces import (
    APIInterface,
    RecipeInterface,
    ClaimValidationResult,
    JSONObject,
    SessionClaimValidator,
)
from typing import Dict, Union, Any
import json
import os
import sys
from functools import wraps
from base64 import b64encode
import time

from django.shortcuts import render
from django.conf import settings
from rest_framework import status  # type: ignore
from rest_framework.decorators import api_view as api_view_sync, renderer_classes  # type: ignore
from adrf.decorators import api_view  # type: ignore
from rest_framework.renderers import StaticHTMLRenderer, BaseRenderer  # type: ignore
from rest_framework.request import Request  # type: ignore
from rest_framework.response import Response  # type: ignore
from supertokens_python import get_all_cors_headers
from supertokens_python import InputAppInfo, Supertokens, SupertokensConfig, init
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.recipe import session
from supertokens_python.recipe.session import (
    InputErrorHandlers,
    SessionContainer,
    SessionRecipe,
)
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    revoke_all_sessions_for_user,
)
from supertokens_python.recipe.session.framework.django.asyncio import verify_session
from supertokens_python.recipe.session.asyncio import merge_into_access_token_payload

from supertokens_python.constants import VERSION
from supertokens_python.types import RecipeUserId
from supertokens_python.utils import is_version_gte
from supertokens_python.recipe.session.asyncio import get_session_information
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

protected_prop_name = {
    "sub",
    "iat",
    "exp",
    "sessionHandle",
    "parentRefreshTokenHash1",
    "refreshTokenHash1",
    "antiCsrfToken",
}

module_dir = os.path.dirname(__file__)  # get current directory
file_path = os.path.join(module_dir, "../templates/index.html")
index_file = open(file_path, "r")
file_contents = index_file.read()
index_file.close()

os.environ.setdefault("SUPERTOKENS_ENV", "testing")

last_set_enable_anti_csrf = True
last_set_enable_jwt = False


class JsonTextRenderer(BaseRenderer):  # type: ignore
    media_type = "application/json"

    def render(self, data, media_type=None, renderer_context=None):  # type: ignore
        if isinstance(data, str):
            return data.encode("utf-8")  # type: ignore
        return json.dumps(data).encode("utf-8")


def custom_decorator_for_test():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        async def wrapped_function(request: Request, *args: Any, **kwargs: Any):  # type: ignore
            Test.increment_attempted_refresh()
            try:
                value: Response = await f(request, *args, **kwargs)  # type: ignore
                if value is not None and value.status_code != 200:  # type: ignore
                    return value  # type: ignore
                if request.headers.get("rid") is None:  # type: ignore
                    return Response("refresh failed")  # type: ignore
                Test.increment_refresh()
                return Response("refresh success")  # type: ignore
            except Exception as e:
                raise e

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_update_jwt():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        async def wrapped_function(request: Request, *args, **kwargs):  # type: ignore
            if request.method == "GET":  # type: ignore
                Test.increment_get_session()
                value: Response = await f(request, *args, **kwargs)  # type: ignore
                if value is not None and value.status_code != 200:  # type: ignore
                    return value  # type: ignore
                session: SessionContainer = request.supertokens  # type: ignore
                resp = Response(  # type: ignore
                    session.get_access_token_payload(),  # type: ignore
                    headers={"Cache-Control": "no-cache, private"},  # type: ignore
                )  # type: ignore
                return resp  # type: ignore
            else:
                if request.method == "POST":  # type: ignore
                    value: Response = await f(request, *args, **kwargs)  # type: ignore
                    if value is not None and value.status_code != 200:  # type: ignore
                        return value  # type: ignore
                    session_: SessionContainer = request.supertokens  # type: ignore

                    clearing = {}
                    for k in session_.get_access_token_payload():  # type: ignore
                        if k not in protected_prop_name:
                            clearing[k] = None

                    body = request.data  # type: ignore
                    await session_.merge_into_access_token_payload(  # type: ignore
                        {**clearing, **body}, {}  # type: ignore
                    )

                    Test.increment_get_session()
                    resp = Response(  # type: ignore
                        session_.get_access_token_payload(),  # type: ignore
                        headers={"Cache-Control": "no-cache, private"},  # type: ignore
                    )  # type: ignore
                    return resp  # type: ignore
            return send_options_api_response()  # type: ignore

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_update_jwt_with_handle():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        async def wrapped_function(request: Request, *args, **kwargs):  # type: ignore
            if request.method == "POST":  # type: ignore
                value: Response = await f(request, *args, **kwargs)  # type: ignore
                if value is not None and value.status_code != 200:  # type: ignore
                    return value  # type: ignore
                session_: SessionContainer = request.supertokens  # type: ignore

                info = await get_session_information(session_.get_handle())  # type: ignore
                assert info is not None
                clearing = {}
                for k in info.custom_claims_in_access_token_payload:
                    if k not in protected_prop_name:
                        clearing[k] = None

                body = request.data  # type: ignore
                await merge_into_access_token_payload(
                    session_.get_handle(), {**clearing, **body}  # type: ignore
                )

                resp = Response(session_.get_access_token_payload())  # type: ignore
                resp["Cache-Control"] = "no-cache, private"
                return resp  # type: ignore
            return send_options_api_response()  # type: ignore

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_get_info():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        async def wrapped_function(request: Request, *args, **kwargs):  # type: ignore
            if request.method == "GET":  # type: ignore
                value: Response = await f(request, *args, **kwargs)  # type: ignore
                if value is not None and value.status_code != 200:  # type: ignore
                    return value  # type: ignore
                Test.increment_get_session()
                session: SessionContainer = request.supertokens  # type: ignore
                resp = Response(  # type: ignore
                    session.get_user_id(),  # type: ignore
                    headers={"Cache-Control": "no-cache, private"},  # type: ignore
                )  # type: ignore
                return resp  # type: ignore
            else:
                return send_options_api_response()  # type: ignore

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_logout():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        async def wrapped_function(request: Request, *args, **kwargs):  # type: ignore
            if request.method == "POST":  # type: ignore
                value: Response = await f(request, *args, **kwargs)  # type: ignore
                if value is not None and value.status_code != 200:  # type: ignore
                    return value  # type: ignore
                session: SessionContainer = request.supertokens  # type: ignore
                await session.revoke_session()  # type: ignore
                return Response("success")  # type: ignore
            return send_options_api_response()  # type: ignore

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


@api_view_sync(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
def try_refresh_token(_):  # type: ignore
    return Response(
        {"error": "try refresh token"},
        status=401,
    )  # type: ignore


@api_view_sync(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
def unauthorised(_):  # type: ignore
    return Response(
        {"error": "unauthorised"},
        content_type="application/json",
        status=401,
    )  # type: ignore


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
        Test.no_of_times_refresh_called_during_test = (
            Test.no_of_times_refresh_called_during_test + 1
        )

    @staticmethod
    def increment_attempted_refresh():
        Test.no_of_times_refresh_attempted_during_test = (
            Test.no_of_times_refresh_attempted_during_test + 1
        )

    @staticmethod
    def increment_get_session():
        Test.no_of_times_get_session_called_during_test = (
            Test.no_of_times_get_session_called_during_test + 1
        )

    @staticmethod
    def get_session_called_count():
        return Test.no_of_times_get_session_called_during_test

    @staticmethod
    def get_refresh_called_count():
        return Test.no_of_times_refresh_called_during_test

    @staticmethod
    def get_refresh_attempted_count():
        return Test.no_of_times_refresh_attempted_during_test


async def unauthorised_f(req: BaseRequest, message: str, res: BaseResponse):
    res.set_status_code(401)
    res.set_json_content({})
    return res


def apis_override_session(param: APIInterface):
    param.disable_refresh_post = True
    return param


def functions_override_session(param: RecipeInterface):
    original_create_new_session = param.create_new_session

    async def create_new_session_custom(
        user_id: str,
        recipe_user_id: RecipeUserId,
        access_token_payload: Union[Dict[str, Any], None],
        session_data_in_database: Union[Dict[str, Any], None],
        disable_anti_csrf: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ):
        if access_token_payload is None:
            access_token_payload = {}
        access_token_payload = {**access_token_payload, "customClaim": "customValue"}
        return await original_create_new_session(
            user_id,
            recipe_user_id,
            access_token_payload,
            session_data_in_database,
            disable_anti_csrf,
            tenant_id,
            user_context,
        )

    param.create_new_session = create_new_session_custom

    return param


def get_app_port():
    argvv = sys.argv
    for i in range(0, len(argvv)):
        if argvv[i] == "--port":
            return argvv[i + 1]

    return "8080"


def config(
    enable_anti_csrf: bool, enable_jwt: bool, _jwt_property_name: Union[str, None]
):
    anti_csrf = "VIA_TOKEN" if enable_anti_csrf else "NONE"

    if enable_jwt:
        if is_version_gte(VERSION, "0.13.0"):
            init(
                supertokens_config=SupertokensConfig("http://localhost:9000"),
                app_info=InputAppInfo(
                    app_name="SuperTokens Python SDK",
                    api_domain="localhost:" + get_app_port(),
                    website_domain="http://localhost.org:8080",
                ),
                framework="django",
                recipe_list=[
                    session.init(
                        error_handlers=InputErrorHandlers(
                            on_unauthorised=unauthorised_f
                        ),
                        anti_csrf=anti_csrf,
                        override=session.InputOverrideConfig(
                            apis=apis_override_session,
                            functions=functions_override_session,
                        ),
                        expose_access_token_to_frontend_in_cookie_based_auth=True,
                    )
                ],
                telemetry=False,
            )
        else:
            init(
                supertokens_config=SupertokensConfig("http://localhost:9000"),
                app_info=InputAppInfo(
                    app_name="SuperTokens Python SDK",
                    api_domain="localhost:" + get_app_port(),
                    website_domain="http://localhost.org:8080",
                ),
                framework="django",
                recipe_list=[
                    session.init(
                        error_handlers=InputErrorHandlers(
                            on_unauthorised=unauthorised_f
                        ),
                        anti_csrf=anti_csrf,
                        override=session.InputOverrideConfig(
                            apis=apis_override_session,
                            functions=functions_override_session,
                        ),
                    )
                ],
                telemetry=False,
            )
    else:
        init(
            supertokens_config=SupertokensConfig("http://localhost:9000"),
            app_info=InputAppInfo(
                app_name="SuperTokens Python SDK",
                api_domain="localhost:" + get_app_port(),
                website_domain="http://localhost.org:8080",
            ),
            framework="django",
            recipe_list=[
                session.init(
                    error_handlers=InputErrorHandlers(on_unauthorised=unauthorised_f),
                    anti_csrf=anti_csrf,
                    override=session.InputOverrideConfig(apis=apis_override_session),
                )
            ],
            telemetry=False,
        )

    for header in get_all_cors_headers():
        assert header in settings.CORS_ALLOW_HEADERS


async def send_file(request: HttpRequest):
    return render(request, file_path)


def send_options_api_response():  # type: ignore
    return Response("")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def login(request: Request):  # type: ignore
    if request.method == "POST":  # type: ignore
        user_id = request.data["userId"]  # type: ignore

        session_ = await create_new_session(request, "public", RecipeUserId(user_id))  # type: ignore
        return Response(session_.get_user_id())  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def login_218(request: Request):  # type: ignore
    if request.method == "POST":  # type: ignore
        request_json = request.data  # type: ignore
        user_id = request_json["userId"]  # type: ignore
        payload = request_json["payload"]  # type: ignore

        querier = Querier.get_instance()
        Querier.api_version = "2.18"

        legacy_session_resp = await querier.send_post_request(
            NormalisedURLPath("/recipe/session"),
            {
                "userId": user_id,
                "enableAntiCsrf": False,
                "userDataInJWT": payload,
                "userDataInDatabase": {},
            },
            {},
        )
        Querier.api_version = None
        front_token = b64encode(
            json.dumps(
                {"uid": user_id, "up": payload, "ate": time.time() * 1000 + 3600000}
            ).encode("utf8")
        ).decode("utf-8")

        return Response(
            "",
            headers={
                "st-access-token": legacy_session_resp["accessToken"]["token"],
                "st-refresh-token": legacy_session_resp["refreshToken"]["token"],
                "front-token": front_token,
            },
        )  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def before_each(request: Request):  # type: ignore
    config(True, False, None)  # type: ignore
    if request.method == "POST":  # type: ignore
        Test.reset()
        return Response("")  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def test_config(request: Request):  # type: ignore
    if request.method == "POST":  # type: ignore
        return Response("")  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def multiple_interceptors(request: Request):  # type: ignore
    if request.method == "POST":  # type: ignore
        result_bool = (
            "success"
            if "interceptorheader2" in request.headers  # type: ignore
            and "interceptorheader1" in request.headers  # type: ignore
            else "failure"
        )
        return Response(result_bool)  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
@custom_decorator_for_get_info()
@verify_session()
async def get_info(request: Request):  # type: ignore
    return Response("")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
def check_rid_no_session(request: Request):  # type: ignore
    rid = request.headers.get("rid")  # type: ignore
    return Response("fail" if rid is None else "success")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
@custom_decorator_for_update_jwt()
@verify_session()
async def update_jwt(request: Request):  # type: ignore
    return Response("")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
@custom_decorator_for_update_jwt_with_handle()
@verify_session()
async def update_jwt_with_handle(request: Request):  # type: ignore
    return Response("")  # type: ignore


def gcv_for_session_claim_err(*_):  # type: ignore
    class CustomValidator(SessionClaimValidator):
        def should_refetch(self, payload: JSONObject, user_context: Dict[str, Any]):
            return False

        async def validate(self, payload: JSONObject, user_context: Dict[str, Any]):
            return ClaimValidationResult(False, {"message": "testReason"})

    return [CustomValidator("test-claim-failing")]


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
@verify_session(override_global_claim_validators=gcv_for_session_claim_err)  # type: ignore
async def session_claim_error_api(request: Request):  # type: ignore
    return Response({})  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def without_body_403(request: Request):  # type: ignore
    if request.method == "POST":  # type: ignore
        return Response("", status=403)  # type: ignore


@api_view(["GET", "POST", "PUT", "DELETE"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def testing(request: Request):  # type: ignore
    if request.method in ["GET", "PUT", "POST", "DELETE"]:  # type: ignore
        if "testing" in request.headers:  # type: ignore
            resp = Response("success")  # type: ignore
            resp["testing"] = request.headers["testing"]  # type: ignore
            return resp  # type: ignore
        return Response("success")  # type: ignore

    # options
    return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
@custom_decorator_for_logout()
@verify_session()
async def logout(request: Request):  # type: ignore
    return Response("")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
@verify_session()
async def revoke_all(request: Request):  # type: ignore
    if request.method:  # type: ignore
        session: Union[None, SessionContainer] = await get_session(request)
        if session is None:
            raise Exception("Should never come here")
        await revoke_all_sessions_for_user(session.get_user_id())
        return Response("success")  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([StaticHTMLRenderer])  # type: ignore
def refresh_attempted_time(request: Request):  # type: ignore
    if request.method == "GET":  # type: ignore
        return Response(str(Test.get_refresh_attempted_count()))  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "PUT", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
@custom_decorator_for_test()
@verify_session()
async def refresh(request: Request):  # type: ignore
    return Response("refresh success")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
def set_anti_csrf(request: Request):  # type: ignore
    global last_set_enable_anti_csrf
    data = request.data  # type: ignore
    if "enableAntiCsrf" not in data:  # type: ignore
        enable_csrf = True
    else:
        enable_csrf = data["enableAntiCsrf"]  # type: ignore

    last_set_enable_anti_csrf = enable_csrf  # type: ignore
    if enable_csrf is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        MultitenancyRecipe.reset()
        OpenIdRecipe.reset()
        OAuth2ProviderRecipe.reset()
        JWTRecipe.reset()
        config(enable_csrf, False, None)  # type: ignore
    return Response("success")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
def set_enable_jwt(request: Request):  # type: ignore
    global last_set_enable_jwt
    global last_set_enable_anti_csrf
    data = request.data  # type: ignore
    if "enableJWT" not in data:  # type: ignore
        enable_jwt = False
    else:
        enable_jwt = data["enableJWT"]  # type: ignore

    last_set_enable_jwt = enable_jwt  # type: ignore
    if enable_jwt is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        MultitenancyRecipe.reset()
        OpenIdRecipe.reset()
        OAuth2ProviderRecipe.reset()
        JWTRecipe.reset()
        config(last_set_enable_anti_csrf, enable_jwt, None)  # type: ignore
    return Response("success")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
def feature_flags(request: Request):  # type: ignore
    global last_set_enable_jwt
    return Response(
        {
            "sessionJwt": last_set_enable_jwt,
            "sessionClaims": is_version_gte(VERSION, "0.11.0"),
            "v3AccessToken": is_version_gte(VERSION, "0.13.0"),
            "duplicateCookieHandling": is_version_gte(VERSION, "0.20.0"),
        }
    )  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def reinitialize(request: Request):  # type: ignore
    global last_set_enable_jwt
    global last_set_enable_anti_csrf
    data = request.data  # type: ignore
    jwt_property_name: Union[str, None] = None
    if "jwtPropertyName" in data:  # type: ignore
        jwt_property_name = data["jwtPropertyName"]  # type: ignore

    Supertokens.reset()
    SessionRecipe.reset()
    MultitenancyRecipe.reset()
    OpenIdRecipe.reset()
    OAuth2ProviderRecipe.reset()
    JWTRecipe.reset()
    config(last_set_enable_anti_csrf, last_set_enable_jwt, jwt_property_name)  # type: ignore
    return Response("")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([StaticHTMLRenderer])  # type: ignore
async def refresh_called_time(request: Request):  # type: ignore
    if request.method == "GET":  # type: ignore
        return Response(str(Test.get_refresh_called_count()))  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([StaticHTMLRenderer])  # type: ignore
async def get_session_called_time(request: Request):  # type: ignore
    if request.method == "GET":  # type: ignore
        return Response(str(Test.get_session_called_count()))  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def ping(request: Request):  # type: ignore
    if request.method == "GET":  # type: ignore
        return Response("success")  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def test_header(request: Request):  # type: ignore
    if request.method == "GET":  # type: ignore
        success_info = request.headers.get("st-custom-header")  # type: ignore
        return Response({"success": success_info})  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def check_device_info(request: Request):  # type: ignore
    if request.method == "GET":  # type: ignore
        sdk_name = request.headers.get("supertokens-sdk-name")  # type: ignore
        sdk_version = request.headers.get("supertokens-sdk-version")  # type: ignore
        return Response(
            "true"
            if sdk_name == "website" and isinstance(sdk_version, str)
            else "false"
        )  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def check_rid(request: Request):  # type: ignore
    rid = request.headers.get("rid")  # type: ignore
    return Response("fail" if rid is None else "success")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def check_allow_credentials(request: Request):  # type: ignore
    if request.method == "GET":  # type: ignore
        return Response("allow-credentials" in request.headers)  # type: ignore
    else:
        return send_options_api_response()  # type: ignore


@api_view(["GET", "POST", "OPTIONS"])
@renderer_classes([JsonTextRenderer])  # type: ignore
async def test_error(request: Request):  # type: ignore
    if request.method == "OPTIONS":  # type: ignore
        return send_options_api_response()  # type: ignore

    status_code = int(request.GET.get("code", "500"))  # type: ignore
    return Response("test error message", status=status_code)  # type: ignore


# @app.exception_handler(405)
# def f_405(_, e):
#     return PlainTextResponse('', status_code=404)


# cors middleware added like this due to issue with add_middleware
# ref: https://github.com/tiangolo/fastapi/issues/1663
