# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.session.interfaces import SessionClaimValidator
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.recipe.session.session_request_functions import (
    get_session_from_request,
)
from supertokens_python.types import MaybeAwaitable

from ..constants import AUTH_PATH, END_SESSION_PATH, LOGIN_PATH

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import SessionContainer
    from supertokens_python.supertokens import AppInfo

    from ..interfaces import (
        ErrorOAuth2Response,
        RecipeInterface,
        RedirectResponse,
    )


async def login_get(
    recipe_implementation: RecipeInterface,
    login_challenge: str,
    session: Optional[SessionContainer],
    should_try_refresh: bool,
    cookies: Optional[List[str]],
    is_direct_call: bool,
    user_context: Dict[str, Any],
) -> Union[RedirectResponse, ErrorOAuth2Response]:
    from ..interfaces import (
        ErrorOAuth2Response,
        FrontendRedirectionURLTypeLogin,
        FrontendRedirectionURLTypeTryRefresh,
        RedirectResponse,
    )

    login_request = await recipe_implementation.get_login_request(
        challenge=login_challenge,
        user_context=user_context,
    )

    if isinstance(login_request, ErrorOAuth2Response):
        return login_request

    session_info = (
        await SessionRecipe.get_instance().recipe_implementation.get_session_information(
            session.get_handle(), user_context
        )
        if session
        else None
    )
    if not session_info:
        session = None

    incoming_auth_url_query_params = parse_qs(urlparse(login_request.request_url).query)
    prompt_param = (
        incoming_auth_url_query_params.get("prompt", [None])[0]
        or incoming_auth_url_query_params.get("st_prompt", [None])[0]
    )
    max_age_param = incoming_auth_url_query_params.get("max_age", [None])[0]

    if max_age_param is not None:
        try:
            max_age_parsed = int(max_age_param)

            if max_age_parsed < 0:
                reject = await recipe_implementation.reject_login_request(
                    challenge=login_challenge,
                    error=ErrorOAuth2Response(
                        error="invalid_request",
                        error_description="max_age cannot be negative",
                    ),
                    user_context=user_context,
                )
                return RedirectResponse(
                    redirect_to=reject.redirect_to,
                    cookies=cookies,
                )

        except ValueError:
            reject = await recipe_implementation.reject_login_request(
                challenge=login_challenge,
                error=ErrorOAuth2Response(
                    error="invalid_request",
                    error_description="max_age must be an integer",
                ),
                user_context=user_context,
            )
            return RedirectResponse(
                redirect_to=reject.redirect_to,
                cookies=cookies,
            )

    tenant_id_param = incoming_auth_url_query_params.get("tenant_id", [None])[0]

    if (
        session
        and session_info
        and (
            not login_request.subject or session.get_user_id() == login_request.subject
        )
        and (not tenant_id_param or session.get_tenant_id() == tenant_id_param)
        and (prompt_param != "login" or is_direct_call)
        and (
            max_age_param is None
            or (max_age_param == "0" and is_direct_call)
            or int(max_age_param) * 1000
            > time.time() * 1000 - session_info.time_created
        )
    ):
        accept = await recipe_implementation.accept_login_request(
            challenge=login_challenge,
            acr=None,
            amr=None,
            context=None,
            extend_session_lifespan=None,
            subject=session.get_user_id(),
            identity_provider_session_id=session.get_handle(),
            user_context=user_context,
        )
        return RedirectResponse(
            redirect_to=accept.redirect_to,
            cookies=cookies,
        )

    if should_try_refresh and prompt_param != "login":
        return RedirectResponse(
            redirect_to=await recipe_implementation.get_frontend_redirection_url(
                params=FrontendRedirectionURLTypeTryRefresh(
                    login_challenge=login_challenge,
                ),
                user_context=user_context,
            ),
            cookies=cookies,
        )

    if prompt_param == "none":
        reject = await recipe_implementation.reject_login_request(
            challenge=login_challenge,
            error=ErrorOAuth2Response(
                error="login_required",
                error_description="The Authorization Server requires End-User authentication. Prompt 'none' was requested, but no existing or expired login session was found.",
            ),
            user_context=user_context,
        )
        return RedirectResponse(
            redirect_to=reject.redirect_to,
            cookies=cookies,
        )

    return RedirectResponse(
        redirect_to=await recipe_implementation.get_frontend_redirection_url(
            params=FrontendRedirectionURLTypeLogin(
                login_challenge=login_challenge,
                force_fresh_auth=session is not None or prompt_param == "login",
                tenant_id=tenant_id_param or DEFAULT_TENANT_ID,
                hint=(
                    login_request.oidc_context.get("login_hint")
                    if login_request.oidc_context
                    else None
                ),
            ),
            user_context=user_context,
        ),
        cookies=cookies,
    )


def get_merged_cookies(orig_cookies: str, new_cookies: Optional[List[str]]) -> str:
    if not new_cookies:
        return orig_cookies

    cookie_map: Dict[str, str] = {}
    for cookie in orig_cookies.split(";"):
        if "=" in cookie:
            name, value = cookie.split("=", 1)
            cookie_map[name.strip()] = value

    # Note: This is a simplified version. In production code you'd want to use a proper
    # cookie parsing library to handle all cookie attributes correctly
    if new_cookies:
        for cookie_str in new_cookies:
            cookie = cookie_str.split(";")[0].strip()
            if "=" in cookie:
                name, value = cookie.split("=", 1)
                cookie_map[name.strip()] = value

    return ";".join(f"{key}={value}" for key, value in cookie_map.items())


def merge_set_cookie_headers(
    set_cookie1: Optional[List[str]] = None, set_cookie2: Optional[List[str]] = None
) -> List[str]:
    if not set_cookie1:
        return set_cookie2 or []
    if not set_cookie2 or set(set_cookie1) == set(set_cookie2):
        return set_cookie1
    return set_cookie1 + set_cookie2


def is_login_internal_redirect(app_info: AppInfo, redirect_to: str) -> bool:
    api_domain = app_info.api_domain.get_as_string_dangerous()
    api_base_path = app_info.api_base_path.get_as_string_dangerous()
    base_path = f"{api_domain}{api_base_path}"

    return any(
        redirect_to.startswith(f"{base_path}{path}") for path in [LOGIN_PATH, AUTH_PATH]
    )


def is_logout_internal_redirect(app_info: AppInfo, redirect_to: str) -> bool:
    api_domain = app_info.api_domain.get_as_string_dangerous()
    api_base_path = app_info.api_base_path.get_as_string_dangerous()
    base_path = f"{api_domain}{api_base_path}"
    return redirect_to.startswith(f"{base_path}{END_SESSION_PATH}")


async def handle_login_internal_redirects(
    app_info: AppInfo,
    response: RedirectResponse,
    recipe_implementation: RecipeInterface,
    session: Optional[SessionContainer],
    should_try_refresh: bool,
    cookie: str,
    user_context: Dict[str, Any],
) -> Union[RedirectResponse, ErrorOAuth2Response]:
    from ..interfaces import ErrorOAuth2Response, RedirectResponse

    if not is_login_internal_redirect(app_info, response.redirect_to):
        return response

    max_redirects = 10
    redirect_count = 0

    while redirect_count < max_redirects and is_login_internal_redirect(
        app_info, response.redirect_to
    ):
        cookie = get_merged_cookies(cookie, response.cookies)

        query_string = (
            response.redirect_to.split("?", 1)[1] if "?" in response.redirect_to else ""
        )
        params = parse_qs(query_string)

        if LOGIN_PATH in response.redirect_to:
            login_challenge = (
                params.get("login_challenge", [None])[0]
                or params.get("loginChallenge", [None])[0]
            )
            if not login_challenge:
                raise Exception(f"Expected loginChallenge in {response.redirect_to}")

            login_res = await login_get(
                recipe_implementation=recipe_implementation,
                login_challenge=login_challenge,
                session=session,
                should_try_refresh=should_try_refresh,
                cookies=response.cookies,
                is_direct_call=False,
                user_context=user_context,
            )

            if isinstance(login_res, ErrorOAuth2Response):
                return login_res

            response = RedirectResponse(
                redirect_to=login_res.redirect_to,
                cookies=merge_set_cookie_headers(login_res.cookies, response.cookies),
            )

        elif AUTH_PATH in response.redirect_to:
            auth_res = await recipe_implementation.authorization(
                params={k: v[0] for k, v in params.items()},
                cookies=cookie,
                session=session,
                user_context=user_context,
            )

            if isinstance(auth_res, ErrorOAuth2Response):
                return auth_res

            response = RedirectResponse(
                redirect_to=auth_res.redirect_to,
                cookies=merge_set_cookie_headers(auth_res.cookies, response.cookies),
            )

        else:
            raise Exception(f"Unexpected internal redirect {response.redirect_to}")

        redirect_count += 1

    return response


async def handle_logout_internal_redirects(
    app_info: AppInfo,
    response: RedirectResponse,
    recipe_implementation: RecipeInterface,
    session: Optional[SessionContainer],
    user_context: Dict[str, Any],
) -> Union[RedirectResponse, ErrorOAuth2Response]:
    if not is_logout_internal_redirect(app_info, response.redirect_to):
        return response

    max_redirects = 10
    redirect_count = 0

    while redirect_count < max_redirects and is_logout_internal_redirect(
        app_info, response.redirect_to
    ):
        query_string = (
            response.redirect_to.split("?", 1)[1] if "?" in response.redirect_to else ""
        )
        params = parse_qs(query_string)

        if END_SESSION_PATH in response.redirect_to:
            end_session_res = await recipe_implementation.end_session(
                params={k: v[0] for k, v in params.items()},
                session=session,
                should_try_refresh=False,
                user_context=user_context,
            )
            if isinstance(end_session_res, ErrorOAuth2Response):
                return end_session_res
            response = end_session_res
        else:
            raise Exception(f"Unexpected internal redirect {response.redirect_to}")

        redirect_count += 1

    return response


async def get_session(
    request: Any,
    session_required: Optional[bool] = None,
    anti_csrf_check: Optional[bool] = None,
    check_database: Optional[bool] = None,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SessionContainer, None]:
    if user_context is None:
        user_context = {}

    if session_required is None:
        session_required = True

    recipe_instance = SessionRecipe.get_instance()
    recipe_interface_impl = recipe_instance.recipe_implementation
    config = recipe_instance.config

    return await get_session_from_request(
        request,
        config,
        recipe_interface_impl,
        session_required=session_required,
        anti_csrf_check=anti_csrf_check,
        check_database=check_database,
        override_global_claim_validators=override_global_claim_validators,
        user_context=user_context,
    )
