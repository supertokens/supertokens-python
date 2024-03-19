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
from typing import Any, Dict, Union
from base64 import b64encode
import time

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.conf import settings
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
from supertokens_python.recipe.session.framework.django.syncio import verify_session
from supertokens_python.recipe.session.interfaces import (
    APIInterface,
    RecipeInterface,
    ClaimValidationResult,
    SessionClaimValidator,
    JSONObject,
)
from supertokens_python.recipe.session.syncio import (
    create_new_session,
    get_session,
    revoke_all_sessions_for_user,
    merge_into_access_token_payload,
)
from supertokens_python.constants import VERSION
from supertokens_python.utils import is_version_gte
from supertokens_python.recipe.session.syncio import get_session_information
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.async_to_sync_wrapper import sync

protected_prop_name = {
    "sub",
    "iat",
    "exp",
    "sessionHandle",
    "parentRefreshTokenHash1",
    "refreshTokenHash1",
    "antiCsrfToken",
}

file_path = "index.html"

os.environ.setdefault("SUPERTOKENS_ENV", "testing")

last_set_enable_anti_csrf = True
last_set_enable_jwt = False


def custom_decorator_for_test():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        def wrapped_function(request: HttpRequest, *args: Any, **kwargs: Any):
            Test.increment_attempted_refresh()
            try:
                value: HttpResponse = f(request, *args, **kwargs)
                if value is not None and value.status_code != 200:
                    return value
                if request.headers.get("rid") is None:  # type: ignore
                    return HttpResponse(content="refresh failed")
                Test.increment_refresh()
                return HttpResponse(content="refresh success")
            except Exception as e:
                raise e

        return wrapped_function

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_update_jwt():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        def wrapped_function(request: HttpRequest, *args, **kwargs):  # type: ignore
            if request.method == "GET":
                Test.increment_get_session()
                value: HttpResponse = f(request, *args, **kwargs)
                if value is not None and value.status_code != 200:
                    return value
                session: SessionContainer = request.supertokens  # type: ignore
                resp = JsonResponse(session.get_access_token_payload())
                resp["Cache-Control"] = "no-cache, private"
                return resp
            else:
                if request.method == "POST":
                    value: HttpResponse = f(request, *args, **kwargs)
                    if value is not None and value.status_code != 200:
                        return value
                    session_: SessionContainer = request.supertokens  # type: ignore

                    clearing = {}
                    for k in session_.get_access_token_payload():
                        if k not in protected_prop_name:
                            clearing[k] = None

                    body = json.loads(request.body)
                    session_.sync_merge_into_access_token_payload(
                        {**clearing, **body}, {}
                    )

                    Test.increment_get_session()
                    resp = JsonResponse(session_.get_access_token_payload())
                    resp["Cache-Control"] = "no-cache, private"
                    return resp
            return send_options_api_response()

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_update_jwt_with_handle():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        def wrapped_function(request: HttpRequest, *args, **kwargs):  # type: ignore
            if request.method == "POST":
                value: HttpResponse = f(request, *args, **kwargs)
                if value is not None and value.status_code != 200:
                    return value
                session_: SessionContainer = request.supertokens  # type: ignore

                info = get_session_information(session_.get_handle())
                assert info is not None
                clearing = {}
                for k in info.custom_claims_in_access_token_payload:
                    if k not in protected_prop_name:
                        clearing[k] = None

                body = json.loads(request.body)
                merge_into_access_token_payload(
                    session_.get_handle(), {**clearing, **body}
                )

                resp = JsonResponse(session_.get_access_token_payload())
                resp["Cache-Control"] = "no-cache, private"
                return resp
            return send_options_api_response()

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_get_info():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        def wrapped_function(request: HttpRequest, *args, **kwargs):  # type: ignore
            if request.method == "GET":
                value: HttpResponse = f(request, *args, **kwargs)
                if value is not None and value.status_code != 200:
                    return value
                Test.increment_get_session()
                session: SessionContainer = request.supertokens  # type: ignore
                resp = HttpResponse(session.get_user_id())
                resp["Cache-Control"] = "no-cache, private"
                return resp
            else:
                return send_options_api_response()

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def custom_decorator_for_logout():  # type: ignore
    def session_verify_custom_test(f):  # type: ignore
        @wraps(f)  # type: ignore
        def wrapped_function(request: HttpRequest, *args, **kwargs):  # type: ignore
            if request.method == "POST":
                value: HttpResponse = f(request, *args, **kwargs)
                if value is not None and value.status_code != 200:
                    return value
                session: SessionContainer = request.supertokens  # type: ignore
                session.sync_revoke_session()
                return HttpResponse("success")
            return send_options_api_response()

        return wrapped_function  # type: ignore

    return session_verify_custom_test  # type: ignore


def try_refresh_token(_):
    return HttpResponse(
        json.dumps({"error": "try refresh token"}),
        content_type="application/json",
        status=401,
    )


def unauthorised(_):
    return HttpResponse(
        json.dumps({"error": "unauthorised"}),
        content_type="application/json",
        status=401,
    )


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


def unauthorised_f(req: BaseRequest, message: str, res: BaseResponse):
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
    for i, _ in enumerate(argvv):
        if argvv[i] == "--port":
            return argvv[i + 1]

    return "8080"


def config(
    enable_anti_csrf: bool, enable_jwt: bool, jwt_property_name: Union[str, None]
):
    anti_csrf = "VIA_TOKEN" if enable_anti_csrf else "NONE"

    if enable_jwt:
        if is_version_gte(VERSION, "0.13.0"):
            init(
                supertokens_config=SupertokensConfig("http://localhost:9000"),
                app_info=InputAppInfo(
                    app_name="SuperTokens Python SDK",
                    api_domain="0.0.0.0:" + get_app_port(),
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
                    api_domain="0.0.0.0:" + get_app_port(),
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
                api_domain="0.0.0.0:" + get_app_port(),
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


config(True, False, None)


def send_file(request: HttpRequest):
    return render(request, file_path)


def send_options_api_response():
    return HttpResponse("")


def login(request: HttpRequest):
    if request.method == "POST":
        user_id = json.loads(request.body)["userId"]

        session_ = create_new_session(request, "public", user_id)
        return HttpResponse(session_.get_user_id())
    else:
        return send_options_api_response()


def login_218(request: HttpRequest):
    if request.method == "POST":
        request_json = json.loads(request.body)
        user_id = request_json["userId"]
        payload = request_json["payload"]

        querier = Querier.get_instance()
        Querier.api_version = "2.18"

        legacy_session_resp = sync(
            querier.send_post_request(
                NormalisedURLPath("/recipe/session"),
                {
                    "userId": user_id,
                    "enableAntiCsrf": False,
                    "userDataInJWT": payload,
                    "userDataInDatabase": {},
                },
                {},
            )
        )
        Querier.api_version = None
        front_token = b64encode(
            json.dumps(
                {"uid": user_id, "up": payload, "ate": time.time() * 1000 + 3600000}
            ).encode("utf8")
        ).decode("utf-8")

        final_response = HttpResponse("")
        final_response["st-access-token"] = legacy_session_resp["accessToken"]["token"]
        final_response["st-refresh-token"] = legacy_session_resp["refreshToken"][
            "token"
        ]
        final_response["front-token"] = front_token
        return final_response
    else:
        return send_options_api_response()


def before_each(request: HttpRequest):
    if request.method == "POST":
        Test.reset()
        return HttpResponse("")
    else:
        return send_options_api_response()


def test_config(request: HttpRequest):
    if request.method == "POST":
        return HttpResponse("")
    else:
        return send_options_api_response()


def multiple_interceptors(request: HttpRequest):
    if request.method == "POST":
        result_bool = (
            "success"
            if "interceptorheader2" in request.headers
            and "interceptorheader1" in request.headers
            else "failure"
        )
        return HttpResponse(result_bool)
    else:
        return send_options_api_response()


@custom_decorator_for_get_info()
@verify_session()
def get_info(request: HttpRequest):
    return HttpResponse("")


def check_rid_no_session(request: HttpRequest):
    rid = request.headers.get("rid")  # type: ignore
    return HttpResponse("fail" if rid is None else "success")


@custom_decorator_for_update_jwt()
@verify_session()
def update_jwt(request: HttpRequest):
    return HttpResponse("")


@custom_decorator_for_update_jwt_with_handle()
@verify_session()
def update_jwt_with_handle(request: HttpRequest):
    return HttpResponse("")


def gcv_for_session_claim_err(*_):  # type: ignore
    class CustomValidator(SessionClaimValidator):
        def should_refetch(self, payload: JSONObject, user_context: Dict[str, Any]):
            return False

        async def validate(self, payload: JSONObject, user_context: Dict[str, Any]):
            return ClaimValidationResult(False, {"message": "testReason"})

    return [CustomValidator("test-claim-failing")]


@verify_session(override_global_claim_validators=gcv_for_session_claim_err)  # type: ignore
def session_claim_error_api(request: HttpRequest):
    return JsonResponse({})


def without_body_403(request: HttpRequest):
    if request.method == "POST":
        return HttpResponse("", status=403)


def testing(request: HttpRequest):
    if request.method in ["GET", "PUT", "POST", "DELETE"]:
        if "testing" in request.headers:
            resp = HttpResponse("success")
            resp["testing"] = request.headers["testing"]
            return resp
        return HttpResponse("success")

    # options
    return send_options_api_response()


@custom_decorator_for_logout()
@verify_session()
def logout(request: HttpRequest):
    return HttpResponse("")


@verify_session()
def revoke_all(request: HttpRequest):
    if request.method:
        session: Union[None, SessionContainer] = get_session(request)
        if session is None:
            raise Exception("Should never come here")
        revoke_all_sessions_for_user(session.get_user_id())
        return HttpResponse("success")
    else:
        return send_options_api_response()


def refresh_attempted_time(request: HttpRequest):
    if request.method == "GET":
        return HttpResponse(Test.get_refresh_attempted_count())
    else:
        return send_options_api_response()


@custom_decorator_for_test()
@verify_session()
def refresh(request: HttpRequest):
    return HttpResponse(content="refresh success")


def set_anti_csrf(request: HttpRequest):
    global last_set_enable_anti_csrf
    data = json.loads(request.body)
    if "enableAntiCsrf" not in data:
        enable_csrf = True
    else:
        enable_csrf = data["enableAntiCsrf"]

    last_set_enable_anti_csrf = enable_csrf
    if enable_csrf is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        MultitenancyRecipe.reset()
        config(enable_csrf, False, None)
    return HttpResponse("success")


def set_enable_jwt(request: HttpRequest):
    global last_set_enable_jwt
    global last_set_enable_anti_csrf
    data = json.loads(request.body)
    if "enableJWT" not in data:
        enable_jwt = False
    else:
        enable_jwt = data["enableJWT"]

    last_set_enable_jwt = enable_jwt
    if enable_jwt is not None:
        Supertokens.reset()
        SessionRecipe.reset()
        MultitenancyRecipe.reset()
        config(last_set_enable_anti_csrf, enable_jwt, None)
    return HttpResponse("success")


def feature_flags(request: HttpRequest):
    global last_set_enable_jwt
    return JsonResponse(
        {
            "sessionJwt": last_set_enable_jwt,
            "sessionClaims": is_version_gte(VERSION, "0.11.0"),
            "v3AccessToken": is_version_gte(VERSION, "0.13.0"),
        }
    )


def reinitialize(request: HttpRequest):
    global last_set_enable_jwt
    global last_set_enable_anti_csrf
    data = json.loads(request.body)
    jwt_property_name: Union[str, None] = None
    if "jwtPropertyName" in data:
        jwt_property_name = data["jwtPropertyName"]

    Supertokens.reset()
    SessionRecipe.reset()
    MultitenancyRecipe.reset()
    config(last_set_enable_anti_csrf, last_set_enable_jwt, jwt_property_name)
    return HttpResponse("")


def refresh_called_time(request: HttpRequest):
    if request.method == "GET":
        return HttpResponse(Test.get_refresh_called_count())
    else:
        return send_options_api_response()


def get_session_called_time(request: HttpRequest):
    if request.method == "GET":
        return HttpResponse(str(Test.get_session_called_count()))
    else:
        return send_options_api_response()


def ping(request: HttpRequest):
    if request.method == "GET":
        return HttpResponse("success")
    else:
        return send_options_api_response()


def test_header(request: HttpRequest):
    if request.method == "GET":
        success_info = request.headers.get("st-custom-header")  # type: ignore
        return JsonResponse({"success": success_info})
    else:
        return send_options_api_response()


def check_device_info(request: HttpRequest):
    if request.method == "GET":
        sdk_name = request.headers.get("supertokens-sdk-name")  # type: ignore
        sdk_version = request.headers.get("supertokens-sdk-version")  # type: ignore
        return HttpResponse(
            "true"
            if sdk_name == "website" and isinstance(sdk_version, str)
            else "false"
        )
    else:
        return send_options_api_response()


def check_rid(request: HttpRequest):
    rid = request.headers.get("rid")  # type: ignore
    return HttpResponse("fail" if rid is None else "success")


def check_allow_credentials(request: HttpRequest):
    if request.method == "GET":
        return JsonResponse(json.dumps("allow-credentials" in request.headers))
    else:
        return send_options_api_response()


def test_error(request: HttpRequest):
    if request.method == "OPTIONS":
        return send_options_api_response()

    status_code = int(request.GET.get("code", "500"))
    return HttpResponse("test error message", status=status_code)


# @app.exception_handler(405)
# def f_405(_, e):
#     return PlainTextResponse('', status_code=404)


# cors middleware added like this due to issue with add_middleware
# ref: https://github.com/tiangolo/fastapi/issues/1663
