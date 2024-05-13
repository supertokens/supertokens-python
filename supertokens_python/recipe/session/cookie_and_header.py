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

from typing import TYPE_CHECKING, List, Optional
from urllib.parse import quote, unquote

from typing_extensions import Literal

from supertokens_python.recipe.session.exceptions import (
    raise_clear_duplicate_session_cookies_exception,
)
from supertokens_python.recipe.session.interfaces import ResponseMutator

from .constants import (
    ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_TOKEN_COOKIE_KEY,
    ACCESS_TOKEN_HEADER_KEY,
    ANTI_CSRF_HEADER_KEY,
    AUTH_MODE_HEADER_KEY,
    AUTHORIZATION_HEADER_KEY,
    FRONT_TOKEN_HEADER_SET_KEY,
    REFRESH_TOKEN_COOKIE_KEY,
    REFRESH_TOKEN_HEADER_KEY,
    RID_HEADER_KEY,
    available_token_transfer_methods,
)
from ...logger import log_debug_message
from supertokens_python.constants import HUNDRED_YEARS_IN_MS

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from .recipe import SessionRecipe
    from .utils import (
        TokenTransferMethod,
        TokenType,
        SessionConfig,
    )

from json import dumps
from typing import Any, Dict

from supertokens_python.utils import get_header, utf_base64encode, get_timestamp_ms


def build_front_token(
    user_id: str, at_expiry: int, access_token_payload: Optional[Dict[str, Any]] = None
):
    if access_token_payload is None:
        access_token_payload = {}
    token_info = {"uid": user_id, "ate": at_expiry, "up": access_token_payload}
    return utf_base64encode(
        dumps(token_info, separators=(",", ":"), sort_keys=True), urlsafe=False
    )


def _set_front_token_in_headers(
    response: BaseResponse,
    front_token: str,
):
    set_header(response, FRONT_TOKEN_HEADER_SET_KEY, front_token, False)
    set_header(
        response, ACCESS_CONTROL_EXPOSE_HEADERS, FRONT_TOKEN_HEADER_SET_KEY, True
    )


def get_cors_allowed_headers():
    return [
        ANTI_CSRF_HEADER_KEY,
        RID_HEADER_KEY,
        AUTHORIZATION_HEADER_KEY,
        AUTH_MODE_HEADER_KEY,
    ]


def set_header(response: BaseResponse, key: str, value: str, allow_duplicate: bool):
    if allow_duplicate:
        old_value = response.get_header(key)
        if old_value is None:
            response.set_header(key, value)
        else:
            response.set_header(key, old_value + "," + value)
    else:
        response.set_header(key, value)


def remove_header(response: BaseResponse, key: str):
    if response.get_header(key) is not None:
        response.remove_header(key)


def get_cookie(request: BaseRequest, key: str):
    cookie_val = request.get_cookie(key)
    if cookie_val is None:
        return None
    return unquote(cookie_val)


def _set_cookie(
    response: BaseResponse,
    config: SessionConfig,
    key: str,
    value: str,
    expires: int,
    path_type: Literal["refresh_token_path", "access_token_path"],
    request: BaseRequest,
    domain: Optional[str],
    user_context: Dict[str, Any],
):
    secure = config.cookie_secure
    same_site = config.get_cookie_same_site(request, user_context)
    path = ""
    if path_type == "refresh_token_path":
        path = config.refresh_token_path.get_as_string_dangerous()
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


def set_cookie_response_mutator(
    config: SessionConfig,
    key: str,
    value: str,
    expires: int,
    path_type: Literal["refresh_token_path", "access_token_path"],
    request: BaseRequest,
    domain: Optional[str] = None,
):
    domain = domain if domain is not None else config.cookie_domain

    def mutator(response: BaseResponse, user_context: Dict[str, Any]):
        return _set_cookie(
            response,
            config,
            key,
            value,
            expires,
            path_type,
            request,
            domain,
            user_context,
        )

    return mutator


def _attach_anti_csrf_header(response: BaseResponse, value: str):
    set_header(response, ANTI_CSRF_HEADER_KEY, value, False)
    set_header(response, ACCESS_CONTROL_EXPOSE_HEADERS, ANTI_CSRF_HEADER_KEY, True)


def anti_csrf_response_mutator(value: str):
    def mutator(
        response: BaseResponse,
        _: Dict[str, Any],
    ):
        return _attach_anti_csrf_header(response, value)

    return mutator


def get_anti_csrf_header(request: BaseRequest):
    return get_header(request, ANTI_CSRF_HEADER_KEY)


def get_rid_header(request: BaseRequest):
    return get_header(request, RID_HEADER_KEY)


def clear_session_from_all_token_transfer_methods(
    response: BaseResponse,
    recipe: SessionRecipe,
    request: BaseRequest,
    user_context: Dict[str, Any],
):
    # We are clearing the session in all transfermethods to be sure to override cookies in case they have been already added to the response.
    # This is done to handle the following use-case:
    # If the app overrides signInPOST to check the ban status of the user after the original implementation and throwing an UNAUTHORISED error
    # In this case: the SDK has attached cookies to the response, but none was sent with the request
    # We can't know which to clear since we can't reliably query or remove the set-cookie header added to the response (causes issues in some frameworks, i.e.: hapi)
    # The safe solution in this case is to overwrite all the response cookies/headers with an empty value, which is what we are doing here.
    for transfer_method in available_token_transfer_methods:
        _clear_session(response, recipe.config, transfer_method, request, user_context)


def clear_session_mutator(
    config: SessionConfig,
    transfer_method: TokenTransferMethod,
    request: BaseRequest,
):
    def mutator(
        response: BaseResponse,
        user_context: Dict[str, Any],
    ):
        return _clear_session(response, config, transfer_method, request, user_context)

    return mutator


def _clear_session(
    response: BaseResponse,
    config: SessionConfig,
    transfer_method: TokenTransferMethod,
    request: BaseRequest,
    user_context: Dict[str, Any],
):
    # If we can be specific about which transferMethod we want to clear, there is no reason to clear the other ones
    token_types: List[TokenType] = ["access", "refresh"]
    for token_type in token_types:
        _set_token(
            response, config, token_type, "", 0, transfer_method, request, user_context
        )

    remove_header(
        response, ANTI_CSRF_HEADER_KEY
    )  # This can be added multiple times in some cases, but that should be OK
    set_header(response, FRONT_TOKEN_HEADER_SET_KEY, "remove", False)
    set_header(
        response, ACCESS_CONTROL_EXPOSE_HEADERS, FRONT_TOKEN_HEADER_SET_KEY, True
    )


def clear_session_response_mutator(
    config: SessionConfig,
    transfer_method: TokenTransferMethod,
    request: BaseRequest,
):
    def mutator(
        response: BaseResponse,
        user_context: Dict[str, Any],
    ):
        return _clear_session(response, config, transfer_method, request, user_context)

    return mutator


def get_cookie_name_from_token_type(token_type: TokenType):
    if token_type == "access":
        return ACCESS_TOKEN_COOKIE_KEY
    if token_type == "refresh":
        return REFRESH_TOKEN_COOKIE_KEY
    raise Exception("Unknown token type, should never happen")


def get_response_header_name_for_token_type(token_type: TokenType):
    if token_type == "access":
        return ACCESS_TOKEN_HEADER_KEY
    if token_type == "refresh":
        return REFRESH_TOKEN_HEADER_KEY
    raise Exception("Unknown token type, should never happen")


def get_token(
    request: BaseRequest,
    token_type: TokenType,
    transfer_method: TokenTransferMethod,
) -> Optional[str]:
    if transfer_method == "cookie":
        # Note: Don't use request.get_cookie() as it won't apply unquote() func
        return get_cookie(request, get_cookie_name_from_token_type(token_type))
    if transfer_method == "header":
        value = request.get_header(AUTHORIZATION_HEADER_KEY)
        if value is None or not value.startswith("Bearer "):
            return None

        return value[len("Bearer ") :].strip()

    raise Exception("Should never happen: Unknown transferMethod: " + transfer_method)


def _set_token(
    response: BaseResponse,
    config: SessionConfig,
    token_type: TokenType,
    value: str,
    expires: int,
    transfer_method: TokenTransferMethod,
    request: BaseRequest,
    user_context: Dict[str, Any],
):
    log_debug_message("Setting %s token as %s", token_type, transfer_method)
    if transfer_method == "cookie":
        _set_cookie(
            response,
            config,
            get_cookie_name_from_token_type(token_type),
            value,
            expires,
            "refresh_token_path" if token_type == "refresh" else "access_token_path",
            request,
            config.cookie_domain,
            user_context,
        )
    elif transfer_method == "header":
        set_token_in_header(
            response,
            get_response_header_name_for_token_type(token_type),
            value,
        )


def token_response_mutator(
    config: SessionConfig,
    token_type: TokenType,
    value: str,
    expires: int,
    transfer_method: TokenTransferMethod,
    request: BaseRequest,
):
    def mutator(
        response: BaseResponse,
        user_context: Dict[str, Any],
    ):
        _set_token(
            response,
            config,
            token_type,
            value,
            expires,
            transfer_method,
            request,
            user_context,
        )

    return mutator


def set_token_in_header(response: BaseResponse, name: str, value: str):
    set_header(response, name, value, allow_duplicate=False)
    set_header(response, ACCESS_CONTROL_EXPOSE_HEADERS, name, allow_duplicate=True)


def access_token_mutator(
    access_token: str,
    front_token: str,
    config: SessionConfig,
    transfer_method: TokenTransferMethod,
    request: BaseRequest,
):
    def mutator(
        response: BaseResponse,
        user_context: Dict[str, Any],
    ):
        _set_access_token_in_response(
            response,
            access_token,
            front_token,
            config,
            transfer_method,
            request,
            user_context,
        )

    return mutator


def _set_access_token_in_response(
    res: BaseResponse,
    access_token: str,
    front_token: str,
    config: SessionConfig,
    transfer_method: TokenTransferMethod,
    request: BaseRequest,
    user_context: Dict[str, Any],
):
    _set_front_token_in_headers(res, front_token)
    _set_token(
        res,
        config,
        "access",
        access_token,
        # We set the expiration to 100 years, because we can't really access the expiration of the refresh token everywhere we are setting it.
        # This should be safe to do, since this is only the validity of the cookie (set here or on the frontend) but we check the expiration of the JWT anyway.
        # Even if the token is expired the presence of the token indicates that the user could have a valid refresh
        # Setting them to infinity would require special case handling on the frontend and just adding 10 years seems enough.
        get_timestamp_ms() + HUNDRED_YEARS_IN_MS,
        transfer_method,
        request,
        user_context,
    )

    if (
        config.expose_access_token_to_frontend_in_cookie_based_auth
        and transfer_method == "cookie"
    ):
        _set_token(
            res,
            config,
            "access",
            access_token,
            get_timestamp_ms() + HUNDRED_YEARS_IN_MS,
            "header",
            request,
            user_context,
        )


# This function addresses an edge case where changing the cookie_domain config on the server can
# lead to session integrity issues. For instance, if the API server URL is 'api.example.com'
# with a cookie domain of '.example.com', and the server updates the cookie domain to 'api.example.com',
# the client may retain cookies with both '.example.com' and 'api.example.com' domains.

# Consequently, if the server chooses the older cookie, session invalidation occurs, potentially
# resulting in an infinite refresh loop. To fix this, users are asked to specify "older_cookie_domain" in
# the config.


# This function checks for multiple cookies with the same name and clears the cookies for the older domain.
def clear_session_cookies_from_older_cookie_domain(
    request: BaseRequest, config: SessionConfig, user_context: Dict[str, Any]
):
    allowed_transfer_method = config.get_token_transfer_method(
        request, False, user_context
    )
    # If the transfer method is 'header', there's no need to clear cookies immediately, even if there are multiple in the request.
    if allowed_transfer_method == "header":
        return

    did_clear_cookies = False
    response_mutators: List[ResponseMutator] = []

    token_types: List[TokenType] = ["access", "refresh"]
    for token_type in token_types:
        if has_multiple_cookies_for_token_type(request, token_type):
            # If a request has multiple session cookies and 'older_cookie_domain' is
            # unset, we can't identify the correct cookie for refreshing the session.
            # Using the wrong cookie can cause an infinite refresh loop. To avoid this,
            # we throw a 500 error asking the user to set 'older_cookie_domain''.
            if config.older_cookie_domain is None:
                raise Exception(
                    "The request contains multiple session cookies. This may happen if you've changed the 'cookie_domain' setting in your configuration. To clear tokens from the previous domain, set 'older_cookie_domain' in your config."
                )

            log_debug_message(
                "Clearing duplicate %s cookie with domain %s",
                token_type,
                config.cookie_domain,
            )
            response_mutators.append(
                set_cookie_response_mutator(
                    config,
                    get_cookie_name_from_token_type(token_type),
                    "",
                    0,
                    (
                        "refresh_token_path"
                        if token_type == "refresh"
                        else "access_token_path"
                    ),
                    request,
                    domain=config.older_cookie_domain,
                )
            )
            did_clear_cookies = True
    if did_clear_cookies:
        raise_clear_duplicate_session_cookies_exception(
            "The request contains multiple session cookies. We are clearing the cookie from older_cookie_domain. Session will be refreshed in the next refresh call.",
            response_mutators=response_mutators,
        )


def has_multiple_cookies_for_token_type(
    request: BaseRequest, token_type: TokenType
) -> bool:
    cookie_string = request.get_header("cookie")
    if cookie_string is None:
        return False

    cookies = _parse_cookie_string_from_request_header_allow_duplicates(cookie_string)
    cookie_name = get_cookie_name_from_token_type(token_type)
    return cookie_name in cookies and len(cookies[cookie_name]) > 1


def _parse_cookie_string_from_request_header_allow_duplicates(
    cookie_string: str,
) -> Dict[str, List[str]]:
    cookies: Dict[str, List[str]] = {}
    cookie_pairs = cookie_string.split(";")
    for cookie_pair in cookie_pairs:
        name_value = cookie_pair.split("=")
        if len(name_value) != 2:
            continue
        name, value = unquote(name_value[0].strip()), unquote(name_value[1].strip())
        if name in cookies:
            cookies[name].append(value)
        else:
            cookies[name] = [value]
    return cookies
