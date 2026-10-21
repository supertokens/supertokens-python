# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distribu/setAntiCsrfted on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governi/setAntiCsrfng permissions and limitations
# under the License./setAntiCsrf
import json
import os
import sys
import time
from base64 import b64encode
from typing import Any, Dict, Union

import uvicorn
from litestar import (
    Litestar,
    MediaType,
    Request,
    Response,
    delete,
    get,
    post,
    put,
    route,
)
from litestar.config.cors import CORSConfig
from litestar.static_files import create_static_files_router  # type: ignore
from supertokens_python import (
    InputAppInfo,
    Supertokens,
    SupertokensConfig,
    get_all_cors_headers,
    init,
)
from supertokens_python.constants import VERSION
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.framework.litestar import (
    create_supertokens_middleware,
    get_exception_handlers,
    get_supertokens_plugin,
)
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe import session
from supertokens_python.recipe.jwt.recipe import JWTRecipe
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.session import InputErrorHandlers
from supertokens_python.recipe.session.asyncio import (
    SessionRecipe,
    create_new_session,
    get_session_information,
    merge_into_access_token_payload,
    revoke_all_sessions_for_user,
)
from supertokens_python.recipe.session.framework.litestar import verify_session
from supertokens_python.recipe.session.interfaces import (
    APIInterface,
    ClaimValidationResult,
    JSONObject,
    RecipeInterface,
    SessionClaimValidator,
)
from supertokens_python.types import RecipeUserId
from supertokens_python.utils import is_version_gte

protected_prop_name = {
    "sub",
    "iat",
    "exp",
    "sessionHandle",
    "parentRefreshTokenHash1",
    "refreshTokenHash1",
    "antiCsrfToken",
}

index_file = open("templates/index.html", "r")
file_contents = index_file.read()
index_file.close()
os.environ.setdefault("SUPERTOKENS_ENV", "testing")

last_set_enable_anti_csrf = True
last_set_enable_jwt = False


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


async def unauthorised_f(_: BaseRequest, __: str, res: BaseResponse):
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
    for i in range(0, len(argvv)):  # pylint: disable=consider-using-enumerate
        if argvv[i] == "--port":
            return argvv[i + 1]

    return "8080"


def config(
    core_url: str,
    enable_anti_csrf: bool,
    enable_jwt: bool,
    jwt_property_name: Union[str, None],
):
    anti_csrf: str = "VIA_TOKEN" if enable_anti_csrf else "NONE"

    if enable_jwt:
        if is_version_gte(VERSION, "0.13.0"):
            init(
                supertokens_config=SupertokensConfig(core_url),
                app_info=InputAppInfo(
                    app_name="SuperTokens Python SDK",
                    api_domain="0.0.0.0:" + get_app_port(),
                    website_domain="http://localhost:8080",
                ),
                framework="litestar",
                recipe_list=[
                    session.init(
                        error_handlers=InputErrorHandlers(
                            on_unauthorised=unauthorised_f
                        ),
                        anti_csrf=anti_csrf,  # type: ignore
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
                supertokens_config=SupertokensConfig(core_url),
                app_info=InputAppInfo(
                    app_name="SuperTokens Python SDK",
                    api_domain="0.0.0.0:" + get_app_port(),
                    website_domain="http://localhost:8080",
                ),
                framework="litestar",
                recipe_list=[
                    session.init(
                        error_handlers=InputErrorHandlers(
                            on_unauthorised=unauthorised_f
                        ),
                        anti_csrf=anti_csrf,  # type: ignore
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
            supertokens_config=SupertokensConfig(core_url),
            app_info=InputAppInfo(
                app_name="SuperTokens Python SDK",
                api_domain="0.0.0.0:" + get_app_port(),
                website_domain="http://localhost:8080",
            ),
            framework="litestar",
            recipe_list=[
                session.init(
                    error_handlers=InputErrorHandlers(on_unauthorised=unauthorised_f),
                    anti_csrf=anti_csrf,  # type: ignore
                    override=session.InputOverrideConfig(apis=apis_override_session),
                )
            ],
            telemetry=False,
        )


core_host = os.environ.get("SUPERTOKENS_CORE_HOST", "localhost")
core_port = os.environ.get("SUPERTOKENS_CORE_PORT", "3567")
config(
    core_url=f"http://{core_host}:{core_port}",
    enable_anti_csrf=True,
    enable_jwt=False,
    jwt_property_name=None,
)


@get("/index.html", media_type=MediaType.HTML, sync_to_thread=True)
def send_file() -> str:
    return file_contents


def send_options_api_response() -> Response[Any]:
    return Response(content="", status_code=200)


@route("/login", http_method=["OPTIONS"], sync_to_thread=True)
def login_options() -> Response[Any]:
    return send_options_api_response()


@post("/login", media_type=MediaType.TEXT)
async def login(request: Request[Any, Any, Any]) -> str:
    user_id = (await request.json())["userId"]
    _session = await create_new_session(request, "public", RecipeUserId(user_id))
    return _session.get_user_id()


@post("/login-2.18", media_type=MediaType.TEXT)
async def login_218(request: Request[Any, Any, Any]) -> Response[Any]:
    request_json = await request.json()
    user_id = request_json["userId"]
    payload = request_json["payload"]

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
        content="",
        headers={
            "st-access-token": legacy_session_resp["accessToken"]["token"],
            "st-refresh-token": legacy_session_resp["refreshToken"]["token"],
            "front-token": front_token,
        },
        status_code=200,
    )


@route("/beforeeach", http_method=["OPTIONS"], sync_to_thread=True)
def before_each_options() -> Response[Any]:
    return send_options_api_response()


@post("/beforeeach", media_type=MediaType.TEXT, sync_to_thread=True)
def before_each() -> str:
    Test.reset()
    return ""


@route("/after", http_method=["OPTIONS"], sync_to_thread=True)
def afer_options() -> Response[Any]:
    return send_options_api_response()


@post("/after", media_type=MediaType.TEXT, sync_to_thread=True)
def afer() -> str:
    Test.reset()
    return ""


@route("/testUserConfig", http_method=["OPTIONS"], sync_to_thread=True)
def test_user_config_options() -> Response[Any]:
    return send_options_api_response()


@post("/testUserConfig", media_type=MediaType.TEXT, sync_to_thread=True)
def test_config() -> str:
    return ""


@route("/multipleInterceptors", http_method=["OPTIONS"], sync_to_thread=True)
def multiple_interceptors_options() -> Response[Any]:
    return send_options_api_response()


@post("/multipleInterceptors", media_type=MediaType.TEXT, sync_to_thread=True)
def multiple_interceptors(request: Request[Any, Any, Any]) -> str:
    result_bool = (
        "success"
        if "interceptorheader2" in request.headers
        and "interceptorheader1" in request.headers
        else "failure"
    )
    return result_bool


@route("/", http_method=["OPTIONS"], sync_to_thread=True)
def options_root() -> Response[Any]:
    return send_options_api_response()


@get("/", media_type=MediaType.TEXT)
async def get_info(request: Request[Any, Any, Any]) -> Response[Any]:
    r_session = await verify_session()(request)
    assert r_session is not None
    Test.increment_get_session()
    return Response(
        content=r_session.get_user_id(),
        headers={"Cache-Control": "no-cache, private"},
        status_code=200,
    )


@get("/check-rid-no-session", media_type=MediaType.TEXT, sync_to_thread=True)
def check_rid_no_session_api(request: Request[Any, Any, Any]) -> str:
    rid = request.headers.get("rid")
    return "failed" if rid is None else "success"


@route("/update-jwt", http_method=["OPTIONS"], sync_to_thread=True)
def update_options() -> Response[Any]:
    return send_options_api_response()


@get("/update-jwt")
async def update_jwt(request: Request[Any, Any, Any]) -> Response[Any]:
    sess = await verify_session()(request)
    assert sess is not None
    Test.increment_get_session()
    return Response(
        content=sess.get_access_token_payload(),
        headers={"Cache-Control": "no-cache, private"},
        status_code=200,
    )


@post("/update-jwt")
async def update_jwt_post(
    request: Request[Any, Any, Any],
) -> Response[Any]:
    _session = await verify_session()(request)
    assert _session is not None
    clearing = {}
    for k in _session.get_access_token_payload():
        if k not in protected_prop_name:
            clearing[k] = None

    body = await request.json()
    await _session.merge_into_access_token_payload({**clearing, **body}, {})

    Test.increment_get_session()
    return Response(
        content=_session.get_access_token_payload(),
        headers={"Cache-Control": "no-cache, private"},
        status_code=200,
    )


@post("/update-jwt-with-handle")
async def update_jwt_with_handle_post(
    request: Request[Any, Any, Any],
) -> Response[Any]:
    _session = await verify_session()(request)
    assert _session is not None
    info = await get_session_information(_session.get_handle())
    assert info is not None
    clearing = {}

    for k in info.custom_claims_in_access_token_payload:
        clearing[k] = None

    body = await request.json()

    await merge_into_access_token_payload(_session.get_handle(), {**clearing, **body})
    return Response(
        content=_session.get_access_token_payload(),
        headers={"Cache-Control": "no-cache, private"},
        status_code=200,
    )


def gcv_for_session_claim_err(*_):  # type: ignore
    class CustomValidator(SessionClaimValidator):
        def should_refetch(self, payload: JSONObject, user_context: Dict[str, Any]):
            return False

        async def validate(self, payload: JSONObject, user_context: Dict[str, Any]):
            return ClaimValidationResult(False, {"message": "testReason"})

    return [CustomValidator("test-claim-failing")]


@post("/session-claims-error")
async def session_claim_error_api(request: Request[Any, Any, Any]) -> Response[Any]:
    await verify_session(override_global_claim_validators=gcv_for_session_claim_err)(  # type: ignore
        request
    )
    return Response(content={}, status_code=200)


@post("/403-without-body", media_type=MediaType.TEXT, sync_to_thread=True)
def without_body_403() -> Response[Any]:
    # send 403 without body
    return Response(content=None, status_code=403)


@route("/testing", http_method=["OPTIONS"], sync_to_thread=True)
def testing_options() -> Response[Any]:
    return send_options_api_response()


@get("/testing", media_type=MediaType.TEXT, sync_to_thread=True)
def testing(request: Request[Any, Any, Any]) -> Response[Any]:
    if "testing" in request.headers:
        return Response(
            content="success",
            headers={"testing": request.headers["testing"]},
            status_code=200,
        )
    return Response(content="success", status_code=200)


@put("/testing", media_type=MediaType.TEXT, sync_to_thread=True)
def testing_put(request: Request[Any, Any, Any]) -> Response[Any]:
    if "testing" in request.headers:
        return Response(
            content="success",
            headers={"testing": request.headers["testing"]},
            status_code=200,
        )
    return Response(content="success", status_code=200)


@post("/testing", media_type=MediaType.TEXT, sync_to_thread=True)
def testing_post(request: Request[Any, Any, Any]) -> Response[Any]:
    if "testing" in request.headers:
        return Response(
            content="success",
            headers={"testing": request.headers["testing"]},
            status_code=200,
        )
    return Response(content="success", status_code=200)


@delete("/testing", media_type=MediaType.TEXT, sync_to_thread=True, status_code=200)
def testing_delete(request: Request[Any, Any, Any]) -> Response[Any]:
    if "testing" in request.headers:
        return Response(
            content="success",
            headers={"testing": request.headers["testing"]},
            status_code=200,
        )
    return Response(content="success", status_code=200)


@route("/logout", http_method=["OPTIONS"], sync_to_thread=True)
def logout_options() -> Response[Any]:
    return send_options_api_response()


@post("/logout", media_type=MediaType.TEXT)
async def logout(request: Request[Any, Any, Any]) -> str:
    _session = await verify_session()(request)
    assert _session is not None
    await _session.revoke_session()
    return "success"


@route("/revokeAll", http_method=["OPTIONS"], sync_to_thread=True)
def revoke_all_options() -> Response[Any]:
    return send_options_api_response()


@post("/revokeAll", media_type=MediaType.TEXT)
async def revoke_all(request: Request[Any, Any, Any]) -> str:
    _session = await verify_session()(request)
    assert _session is not None
    await revoke_all_sessions_for_user(_session.get_user_id())
    return "success"


@route("/refresh", http_method=["OPTIONS"], sync_to_thread=True)
def refresh_options() -> Response[Any]:
    return send_options_api_response()


@get("/refreshAttemptedTime", media_type=MediaType.TEXT, sync_to_thread=True)
def refresh_attempted_time() -> Response[Any]:
    return Response(content=str(Test.get_refresh_attempted_count()), status_code=200)


@post("/auth/session/refresh", media_type=MediaType.TEXT)
async def refresh(request: Request[Any, Any, Any]) -> str:
    Test.increment_attempted_refresh()
    try:
        await verify_session()(request)
    except Exception as e:
        raise e

    if request.headers.get("rid") is None:
        return "refresh failed"
    Test.increment_refresh()
    return "refresh success"


@route("/refreshCalledTime", http_method=["OPTIONS"], sync_to_thread=True)
def refresh_called_time_options() -> Response[Any]:
    return send_options_api_response()


@get("/refreshCalledTime", media_type=MediaType.TEXT, sync_to_thread=True)
def refresh_called_time() -> Response[Any]:
    return Response(content=str(Test.get_refresh_called_count()), status_code=200)


@route("/getSessionCalledTime", http_method=["OPTIONS"], sync_to_thread=True)
def get_session_called_time_options() -> Response[Any]:
    return send_options_api_response()


@get("/getSessionCalledTime", media_type=MediaType.TEXT, sync_to_thread=True)
def get_session_called_time() -> Response[Any]:
    return Response(content=str(Test.get_session_called_count()), status_code=200)


@route("/ping", http_method=["OPTIONS"], sync_to_thread=True)
def ping_options() -> Response[Any]:
    return send_options_api_response()


@get("/ping", media_type=MediaType.TEXT, sync_to_thread=True)
def ping() -> str:
    return "success"


@route("/testHeader", http_method=["OPTIONS"], sync_to_thread=True)
def test_header_options() -> Response[Any]:
    return send_options_api_response()


@get("/testHeader", sync_to_thread=True)
def test_header(request: Request[Any, Any, Any]) -> Response[Any]:
    success_info = request.headers.get("st-custom-header")
    return Response({"success": success_info}, status_code=200)


@route("/checkDeviceInfo", http_method=["OPTIONS"], sync_to_thread=True)
def check_device_info_options() -> Response[Any]:
    return send_options_api_response()


@get("/checkDeviceInfo", media_type=MediaType.TEXT, sync_to_thread=True)
def check_device_info(request: Request[Any, Any, Any]) -> str:
    sdk_name = request.headers.get("supertokens-sdk-name")
    sdk_version = request.headers.get("supertokens-sdk-version")
    return "true" if sdk_name == "website" and isinstance(sdk_version, str) else "false"


@get("/check-rid", media_type=MediaType.TEXT, sync_to_thread=True)
def check_rid(request: Request[Any, Any, Any]) -> str:
    rid = request.headers.get("rid")

    return "fail" if rid is None else "success"


@get("/featureFlags", sync_to_thread=True)
def feature_flags(_: Request[Any, Any, Any]) -> Response[Any]:
    # print("Got into feature flags")
    global last_set_enable_jwt  # pylint: disable=global-variable-not-assigned

    return Response(
        {
            "sessionJwt": last_set_enable_jwt,
            "sessionClaims": is_version_gte(VERSION, "0.11.0"),
            "v3AccessToken": is_version_gte(VERSION, "0.13.0"),
            "duplicateCookieHandling": is_version_gte(VERSION, "0.20.0"),
        }
    )


@post("/reinitialiseBackendConfig", media_type=MediaType.TEXT)
async def reinitialize(request: Request[Any, Any, Any]) -> str:
    global last_set_enable_jwt  # pylint: disable=global-variable-not-assigned
    global last_set_enable_anti_csrf  # pylint: disable=global-variable-not-assigned
    json = await request.json()
    if "jwtPropertyName" not in json:
        jwt_property_name = None
    else:
        jwt_property_name = json["jwtPropertyName"]

    Supertokens.reset()
    SessionRecipe.reset()
    MultitenancyRecipe.reset()
    OpenIdRecipe.reset()
    OAuth2ProviderRecipe.reset()
    JWTRecipe.reset()
    config(
        json["coreUrl"],
        last_set_enable_anti_csrf,
        last_set_enable_jwt,
        jwt_property_name,
    )
    return ""


@post("/test/setup/st", media_type=MediaType.TEXT)
async def setup_st(request: Request[Any, Any, Any]) -> str:
    global last_set_enable_jwt
    global last_set_enable_anti_csrf
    json = await request.json()

    Supertokens.reset()
    SessionRecipe.reset()
    MultitenancyRecipe.reset()
    OpenIdRecipe.reset()
    OAuth2ProviderRecipe.reset()
    JWTRecipe.reset()
    config(
        core_url=json["coreUrl"],
        enable_anti_csrf=json.get("enableAntiCsrf"),
        enable_jwt=json.get("enableJWT"),
        jwt_property_name=json.get("jwtPropertyName"),
    )

    last_set_enable_anti_csrf = json.get("enableAntiCsrf")
    last_set_enable_jwt = json.get("enableJWT")
    return ""


@route("/checkAllowCredentials", http_method=["OPTIONS"], sync_to_thread=True)
def check_allow_credentials_options() -> Response[Any]:
    return send_options_api_response()


@get("/checkAllowCredentials", media_type=MediaType.TEXT, sync_to_thread=True)
def check_allow_credentials(request: Request[Any, Any, Any]) -> Response[Any]:
    return Response(
        content=json.dumps("allow-credentials" in request.headers), status_code=200
    )


@route(
    "/testError",
    media_type=MediaType.TEXT,
    http_method=["OPTIONS", "GET", "POST"],
    sync_to_thread=True,
)
def test_error(request: Request[Any, Any, Any]) -> Response[Any]:
    if request.method == "OPTIONS":
        return send_options_api_response()

    status_code = int(request.query_params.get("code", "500"))
    return Response(content="test error message", status_code=status_code)


# Create static files router for angular templates
static_files_router = create_static_files_router(
    path="/angular",
    directories=["templates/angular"],
    name="angular",
)

# Initialize Litestar app with all configurations
app = Litestar(
    route_handlers=[
        send_file,
        login_options,
        login,
        login_218,
        before_each_options,
        before_each,
        afer_options,
        afer,
        test_user_config_options,
        test_config,
        multiple_interceptors_options,
        multiple_interceptors,
        options_root,
        get_info,
        check_rid_no_session_api,
        update_options,
        update_jwt,
        update_jwt_post,
        update_jwt_with_handle_post,
        session_claim_error_api,
        without_body_403,
        testing_options,
        testing,
        testing_put,
        testing_post,
        testing_delete,
        logout_options,
        logout,
        revoke_all_options,
        revoke_all,
        refresh_options,
        refresh_attempted_time,
        refresh,
        refresh_called_time_options,
        refresh_called_time,
        get_session_called_time_options,
        get_session_called_time,
        ping_options,
        ping,
        test_header_options,
        test_header,
        check_device_info_options,
        check_device_info,
        check_rid,
        feature_flags,
        reinitialize,
        setup_st,
        check_allow_credentials_options,
        check_allow_credentials,
        test_error,
        static_files_router,
    ],
    cors_config=CORSConfig(
        allow_origins=["http://localhost:8080"],
        allow_credentials=True,
        allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["Content-Type"] + get_all_cors_headers(),
    ),
    plugins=[get_supertokens_plugin()],
    middleware=[create_supertokens_middleware()],
    exception_handlers=get_exception_handlers(),
    debug=True,
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)  # type: ignore
