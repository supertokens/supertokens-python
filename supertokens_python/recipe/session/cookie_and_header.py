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
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote, unquote

from typing_extensions import Literal

from .constants import (
    ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_TOKEN_COOKIE_KEY,
    ANTI_CSRF_HEADER_KEY,
    FRONT_TOKEN_HEADER_SET_KEY,
    ID_REFRESH_TOKEN_COOKIE_KEY,
    ID_REFRESH_TOKEN_HEADER_SET_KEY,
    REFRESH_TOKEN_COOKIE_KEY,
    RID_HEADER_KEY,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from .recipe import SessionRecipe

from json import dumps
from typing import Any, Dict, Union

from supertokens_python.exceptions import raise_general_exception
from supertokens_python.utils import get_header, utf_base64encode


def set_front_token_in_headers(
    response: BaseResponse,
    user_id: str,
    expires_at: int,
    jwt_payload: Union[None, Dict[str, Any]] = None,
):
    if jwt_payload is None:
        jwt_payload = {}
    token_info = {"uid": user_id, "ate": expires_at, "up": jwt_payload}
    set_header(
        response,
        FRONT_TOKEN_HEADER_SET_KEY,
        utf_base64encode(dumps(token_info, separators=(",", ":"), sort_keys=True)),
        False,
    )
    set_header(
        response, ACCESS_CONTROL_EXPOSE_HEADERS, FRONT_TOKEN_HEADER_SET_KEY, True
    )


def get_cors_allowed_headers():
    return [ANTI_CSRF_HEADER_KEY, RID_HEADER_KEY]


def set_header(response: BaseResponse, key: str, value: str, allow_duplicate: bool):
    try:
        if allow_duplicate:
            old_value = response.get_header(key)
            if old_value is None:
                response.set_header(key, value)
            else:
                response.set_header(key, old_value + "," + value)
        else:
            response.set_header(key, value)
    except Exception:
        raise_general_exception(
            "Error while setting header with key: " + key + " and value: " + value
        )


def get_cookie(request: BaseRequest, key: str):
    cookie_val = request.get_cookie(key)
    if cookie_val is None:
        return None
    return unquote(cookie_val)


def set_cookie(
    recipe: SessionRecipe,
    response: BaseResponse,
    key: str,
    value: str,
    expires: int,
    path_type: Literal["refresh_token_path", "access_token_path"],
):
    domain = recipe.config.cookie_domain
    secure = recipe.config.cookie_secure
    same_site = recipe.config.cookie_same_site
    path = ""
    if path_type == "refresh_token_path":
        path = recipe.config.refresh_token_path.get_as_string_dangerous()
    elif path_type == "access_token_path":
        path = "/"
    http_only = True
    response.set_cookie(
        key=key,
        value=quote(value, encoding="utf-8"),
        expires=expires,
        path=path,
        domain=domain,
        secure=secure,
        httponly=http_only,
        samesite=same_site,
    )


def attach_anti_csrf_header(response: BaseResponse, value: str):
    set_header(response, ANTI_CSRF_HEADER_KEY, value, False)
    set_header(response, ACCESS_CONTROL_EXPOSE_HEADERS, ANTI_CSRF_HEADER_KEY, True)


def get_anti_csrf_header(request: BaseRequest):
    return get_header(request, ANTI_CSRF_HEADER_KEY)


def get_rid_header(request: BaseRequest):
    return get_header(request, RID_HEADER_KEY)


def attach_access_token_to_cookie(
    recipe: SessionRecipe, response: BaseResponse, token: str, expires_at: int
):
    set_cookie(
        recipe,
        response,
        ACCESS_TOKEN_COOKIE_KEY,
        token,
        expires_at,
        "access_token_path",
    )


def attach_refresh_token_to_cookie(
    recipe: SessionRecipe, response: BaseResponse, token: str, expires_at: int
):
    set_cookie(
        recipe,
        response,
        REFRESH_TOKEN_COOKIE_KEY,
        token,
        expires_at,
        "refresh_token_path",
    )


def attach_id_refresh_token_to_cookie_and_header(
    recipe: SessionRecipe, response: BaseResponse, token: str, expires_at: int
):
    set_header(
        response, ID_REFRESH_TOKEN_HEADER_SET_KEY, token + ";" + str(expires_at), False
    )
    set_header(
        response, ACCESS_CONTROL_EXPOSE_HEADERS, ID_REFRESH_TOKEN_HEADER_SET_KEY, True
    )
    set_cookie(
        recipe,
        response,
        ID_REFRESH_TOKEN_COOKIE_KEY,
        token,
        expires_at,
        "access_token_path",
    )


def get_access_token_from_cookie(request: BaseRequest):
    return get_cookie(request, ACCESS_TOKEN_COOKIE_KEY)


def get_refresh_token_from_cookie(request: BaseRequest):
    return get_cookie(request, REFRESH_TOKEN_COOKIE_KEY)


def get_id_refresh_token_from_cookie(request: BaseRequest):
    return get_cookie(request, ID_REFRESH_TOKEN_COOKIE_KEY)


def clear_cookies(recipe: SessionRecipe, response: BaseResponse):
    set_cookie(recipe, response, ACCESS_TOKEN_COOKIE_KEY, "", 0, "access_token_path")
    set_cookie(
        recipe, response, ID_REFRESH_TOKEN_COOKIE_KEY, "", 0, "access_token_path"
    )
    set_cookie(recipe, response, REFRESH_TOKEN_COOKIE_KEY, "", 0, "refresh_token_path")
    set_header(response, ID_REFRESH_TOKEN_HEADER_SET_KEY, "remove", False)
    set_header(
        response,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ID_REFRESH_TOKEN_HEADER_SET_KEY,
        True,
    )
