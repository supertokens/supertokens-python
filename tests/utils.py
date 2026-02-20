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
import asyncio
import json

# Import AsyncMock
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from http.cookies import SimpleCookie
from os import environ
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast
from unittest.mock import MagicMock
from urllib.parse import unquote
from uuid import uuid4

import requests
from fastapi.testclient import TestClient
from httpx import Response as HTTPXResponse
from pytest import mark
from requests.models import Response as RequestsResponse
from supertokens_python import InputAppInfo, Supertokens, SupertokensConfig
from supertokens_python.process_state import ProcessState
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.dashboard import DashboardRecipe
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.jwt import JWTRecipe
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.passwordless import PasswordlessRecipe
from supertokens_python.recipe.passwordless.asyncio import consume_code, create_code
from supertokens_python.recipe.saml.recipe import SAMLRecipe
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.asyncio import manually_create_or_update_user
from supertokens_python.recipe.totp.recipe import TOTPRecipe
from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.userroles import UserRolesRecipe
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.utils import is_version_gte

API_VERSION_TEST_NON_SUPPORTED_SV = ["0.0", "1.0", "1.1", "2.1"]
API_VERSION_TEST_NON_SUPPORTED_CV = ["0.1", "0.2", "1.2", "2.0", "3.0"]
API_VERSION_TEST_MULTIPLE_SUPPORTED_SV = ["0.0", "1.0", "1.1", "2.1"]
API_VERSION_TEST_MULTIPLE_SUPPORTED_CV = ["0.1", "0.2", "1.1", "2.1", "3.0"]
API_VERSION_TEST_MULTIPLE_SUPPORTED_RESULT = "2.1"
API_VERSION_TEST_SINGLE_SUPPORTED_SV = ["0.0", "1.0", "1.1", "2.0"]
API_VERSION_TEST_SINGLE_SUPPORTED_CV = ["0.1", "0.2", "1.1", "2.1", "3.0"]
API_VERSION_TEST_SINGLE_SUPPORTED_RESULT = "1.1"
API_VERSION_TEST_BASIC_RESULT = ["2.0", "2.1", "2.2", "2.3", "2.9"]
SUPPORTED_CORE_DRIVER_INTERFACE_FILE = "./coreDriverInterfaceSupported.json"
TEST_ACCESS_TOKEN_MAX_AGE_VALUE: str = "7200"  # seconds
TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY = "access_token_validity"
TEST_REFRESH_TOKEN_MAX_AGE_VALUE: str = "720"  # minutes
TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY = "refresh_token_validity"
TEST_DRIVER_CONFIG_COOKIE_DOMAIN = "supertokens.io"
TEST_DRIVER_CONFIG_COOKIE_SAME_SITE = "lax"
TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH = "/"
TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH = "/auth/session/refresh"
ACCESS_CONTROL_EXPOSE_HEADER = "Access-Control-Expose-Headers"
ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE = (
    "front-token, id-refresh-token, anti-csrf"
)
ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE = "id-refresh-token"
TEST_ID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def get_new_core_app_url(
    *,
    host: str = environ.get("SUPERTOKENS_CORE_HOST", "localhost"),
    port: str = environ.get("SUPERTOKENS_CORE_PORT", "3567"),
    core_config: Optional[Dict[str, str]] = None,
) -> str:
    """
    Create a new application in the ST core, and return a URL to use it.
    """
    core_url = f"http://{host}:{port}"

    if core_config is None:
        core_config = {}

    app_id = str(uuid4())

    response = requests.put(
        f"{core_url}/recipe/multitenancy/app/v2",
        headers={
            "Content-Type": "application/json",
        },
        json={
            "appId": app_id,
            "coreConfig": core_config,
        },
    )

    assert response.status_code == 200, (
        f"ST Core App creation failed with: {response.text}"
    )

    res_json = response.json()
    assert res_json["status"] == "OK"
    assert res_json["createdNew"]

    return f"{core_url}/appid-{app_id}"


def reset():
    ProcessState.get_instance().reset()
    Supertokens.reset()
    SessionRecipe.reset()
    EmailPasswordRecipe.reset()
    EmailVerificationRecipe.reset()
    ThirdPartyRecipe.reset()
    PasswordlessRecipe.reset()
    JWTRecipe.reset()
    UserMetadataRecipe.reset()
    UserRolesRecipe.reset()
    DashboardRecipe.reset()
    PasswordlessRecipe.reset()
    MultitenancyRecipe.reset()
    AccountLinkingRecipe.reset()
    MultiFactorAuthRecipe.reset()
    TOTPRecipe.reset()
    OpenIdRecipe.reset()
    OAuth2ProviderRecipe.reset()
    SAMLRecipe.reset()
    WebauthnRecipe.reset()


def get_cookie_from_response(
    response: Union[RequestsResponse, HTTPXResponse], cookie_name: str
):
    cookies = extract_all_cookies(response)
    if cookie_name in cookies:
        return cookies[cookie_name]
    return None


def extract_all_cookies(
    response: Union[RequestsResponse, HTTPXResponse],
) -> Dict[str, Any]:
    if response.headers.get("set-cookie") is None:
        return {}
    cookie_headers = SimpleCookie(response.headers.get("set-cookie"))  # type: ignore
    cookies: Dict[str, Any] = {}
    for key, morsel in cookie_headers.items():  # type: ignore
        cookies[key] = {"value": morsel.value, "name": key}
        for k, v in morsel.items():
            if (k in ("secure", "httponly")) and v == "":
                cookies[key][k] = None
            elif k == "samesite":
                if len(v) > 0 and v[-1] == ",":
                    v = v[:-1]
                cookies[key][k] = v
            else:
                cookies[key][k] = v
    return cookies


def extract_info(response: Union[RequestsResponse, HTTPXResponse]) -> Dict[str, Any]:
    cookies = extract_all_cookies(response)
    access_token = cookies.get("sAccessToken", {}).get("value")
    refresh_token = cookies.get("sRefreshToken", {}).get("value")

    access_token_from_header = response.headers.get("st-access-token")
    refresh_token_from_header = response.headers.get("st-refresh-token")

    return {
        **cookies,
        "accessToken": None if access_token is None else unquote(access_token),
        "refreshToken": None if refresh_token is None else unquote(refresh_token),
        "frontToken": response.headers.get("front-token"),
        "status_code": response.status_code,
        "body": response.json(),
        "antiCsrf": response.headers.get("anti-csrf"),
        "accessTokenFromHeader": access_token_from_header,
        "refreshTokenFromHeader": refresh_token_from_header,
        "accessTokenFromAny": (
            access_token_from_header if access_token is None else access_token
        ),
        "refreshTokenFromAny": (
            refresh_token_from_header if refresh_token is None else refresh_token
        ),
    }


def assert_info_clears_tokens(info: Dict[str, Any], token_transfer_method: str):
    if token_transfer_method == "cookie":
        assert info["accessToken"] == ""
        assert info["refreshToken"] == ""
        assert info["sAccessToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
        assert info["sRefreshToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
        assert info["sAccessToken"]["domain"] == ""
        assert info["sRefreshToken"]["domain"] == ""
    elif token_transfer_method == "header":
        assert info["accessTokenFromHeader"] == ""
        assert info["refreshTokenFromHeader"] == ""
    else:
        raise Exception("unknown token transfer method: " + token_transfer_method)

    assert info["frontToken"] == "remove"
    assert info["antiCsrf"] is None


def get_unix_timestamp(expiry: str):
    return int(
        datetime.strptime(expiry, "%a, %d %b %Y %H:%M:%S GMT")
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )


def verify_within_5_second_diff(n1: int, n2: int):
    return -5 <= (n1 - n2) <= 5


def sign_up_request(app: TestClient, email: str, password: str):
    return app.post(
        url="/auth/signup",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "password", "value": password},
                {"id": "email", "value": email},
            ]
        },
    )


def sign_in_up_request(app: TestClient, email: str, use_server: bool = False):
    if use_server:
        environ["SUPERTOKENS_ENV"] = "production"
    try:
        response = app.post(
            url="/auth/signinup/code",
            headers={"Content-Type": "application/json"},
            json={"email": email},
        )
        return response
    finally:
        if use_server:
            environ["SUPERTOKENS_ENV"] = "testing"


def sign_in_up_request_phone(app: TestClient, phone: str, use_server: bool = False):
    if use_server:
        environ["SUPERTOKENS_ENV"] = "production"
    try:
        response = app.post(
            url="/auth/signinup/code",
            headers={"Content-Type": "application/json"},
            json={"phoneNumber": phone},
        )
        return response
    finally:
        if use_server:
            environ["SUPERTOKENS_ENV"] = "testing"


def sign_in_up_request_code_resend(
    app: TestClient, device_id: str, preauth_sesion_id: str, use_server: bool = False
):
    if use_server:
        environ["SUPERTOKENS_ENV"] = "production"
    try:
        response = app.post(
            url="/auth/signinup/code/resend",
            headers={"Content-Type": "application/json"},
            json={"deviceId": device_id, "preAuthSessionId": preauth_sesion_id},
        )
        return response
    finally:
        if use_server:
            environ["SUPERTOKENS_ENV"] = "testing"


def reset_password_request(app: TestClient, email: str, use_server: bool = False):
    if use_server:
        environ["SUPERTOKENS_ENV"] = "production"
    try:
        response = app.post(
            url="/auth/user/password/reset/token",
            json={"formFields": [{"id": "email", "value": email}]},
        )
        return response
    finally:
        if use_server:
            environ["SUPERTOKENS_ENV"] = "testing"


def sign_in_request(app: TestClient, email: str, password: str):
    return app.post(
        url="/auth/signin",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "password", "value": password},
                {"id": "email", "value": email},
            ]
        },
    )


def email_verify_token_request(
    app: TestClient,
    accessToken: str,
    antiCsrf: Optional[str],
    userId: str,
    use_server: bool = False,
):
    if use_server:
        environ["SUPERTOKENS_ENV"] = "production"
    try:
        headers = {
            "Content-Type": "application/json",
        }
        if antiCsrf:
            headers["anti-csrf"] = antiCsrf

        resp = app.post(
            url="/auth/user/email/verify/token",
            headers=headers,
            cookies={
                "sAccessToken": accessToken,
            },
            data=userId,  # type: ignore
        )
        return resp
    finally:
        if use_server:
            environ["SUPERTOKENS_ENV"] = "testing"


# Cache the output to make sure this is only computed once
@lru_cache
def get_core_api_version() -> str:
    """
    Fetches the core api version only once
    """
    from supertokens_python import init
    from supertokens_python.querier import Querier
    from supertokens_python.recipe import session

    loop = asyncio.get_event_loop()

    async def get_api_version():
        return await Querier.get_instance().get_api_version()

    try:
        # If ST has been already initialized:
        core_version = cast(  # type: ignore
            loop.run_until_complete(asyncio.gather(get_api_version())),  # type: ignore
            str,
        )
        return core_version  # type: ignore
    except Exception:
        pass

    reset()
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    api_version = asyncio.gather(get_api_version())
    core_version = loop.run_until_complete(api_version)[0]  # type: ignore # pylint: disable=unused-variable
    reset()
    return core_version


def min_api_version(min_version: str) -> Any:
    """
    Skips the test if the local ST core doesn't satisfy
    version requirements for the tests.
    Fetches the core version only once throughout the testing session.
    """

    def wrapper(f: Any) -> Any:
        core_api_version = get_core_api_version()
        if is_version_gte(core_api_version, min_version):
            return mark.asyncio(f)

        return mark.skip(f"Requires core api version >= {min_version}")(f)

    return wrapper


if sys.version_info >= (3, 8):
    from unittest.mock import AsyncMock

    _ = AsyncMock
else:

    class AsyncMock(MagicMock):
        async def __call__(  # pylint: disable=invalid-overridden-method, useless-super-delegation
            self,  # type: ignore
            *args,  # type: ignore
            **kwargs,  # type: ignore
        ):
            return super().__call__(*args, **kwargs)


def get_st_init_args(*, url: str, recipe_list: List[Any]) -> Dict[str, Any]:
    return {
        "supertokens_config": SupertokensConfig(url),
        "app_info": InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        "framework": "fastapi",
        "mode": "asgi",
        "recipe_list": recipe_list,
    }


def is_subset(dict1: Any, dict2: Any) -> bool:
    """Check if dict2 is subset of dict1 in a nested manner
    Iteratively compares list items with recursion if key's value is a list
    """
    if isinstance(dict1, list):
        if isinstance(dict2, list):
            for item in dict2:  # type: ignore
                if item not in dict1:
                    return False
            return True
        return False
    if isinstance(dict1, dict):
        if isinstance(dict2, dict):
            for key, value in dict2.items():  # type: ignore
                if key not in dict1:
                    return False
                if not is_subset(dict1[key], value):
                    return False
            return True
        return False

    return dict1 == dict2


async def create_users(
    emailpassword: bool = False, passwordless: bool = False, thirdparty: bool = False
):
    with open(
        Path(__file__).parent / "./users.json",
        "r",
    ) as json_data:
        users = json.loads(json_data.read())["users"]
    for user in users:
        if user["recipe"] == "emailpassword" and emailpassword:
            await sign_up("public", user["email"], user["password"])
        elif user["recipe"] == "passwordless" and passwordless:
            if user.get("email"):
                coderesponse = await create_code("public", user["email"])
                await consume_code(
                    "public",
                    coderesponse.pre_auth_session_id,
                    coderesponse.user_input_code,
                    coderesponse.device_id,
                )
            else:
                coderesponse = await create_code("public", None, user["phone"])
                await consume_code(
                    "public",
                    coderesponse.pre_auth_session_id,
                    coderesponse.user_input_code,
                    coderesponse.device_id,
                )
        elif user["recipe"] == "thirdparty" and thirdparty:
            await manually_create_or_update_user(
                "public", user["provider"], user["userId"], user["email"], True, None
            )


@contextmanager
def outputs(value: Any):
    """
    Outputs a value to assert.
    Can be used for a common interface in test parameters.

    Example:
    ```python
    @mark.parametrize(
    ("input", "expectation"),
        [
            (1, outputs(1)),
            (0, raises(Exception)),
        ]
    )
    def test(input, expectation):
        # In case of exceptions, the `raises` will catch it
        # In normal execution, the `expected_output` contains the assertion value
        with expectation as expected_output:
            assert 1 / input == expected_output
    ```
    """
    yield value
