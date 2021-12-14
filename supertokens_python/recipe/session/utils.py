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

from typing import TYPE_CHECKING, Callable, Union, Awaitable, Literal
from urllib.parse import urlparse

from tldextract import extract

from supertokens_python.exceptions import raise_general_exception
from supertokens_python.framework import BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.utils import is_an_ip_address, send_non_200_response
from .constants import SESSION_REFRESH
from .cookie_and_header import clear_cookies
from supertokens_python.recipe.openid import InputOverrideConfig as OpenIdInputOverrideConfig
from .with_jwt.constants import ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY, JWT_RESERVED_KEY_USE_ERROR_MESSAGE

if TYPE_CHECKING:
    from .interfaces import RecipeInterface, APIInterface
    from supertokens_python.framework import BaseRequest
    from .recipe import SessionRecipe
    from supertokens_python.supertokens import AppInfo


def normalise_session_scope(recipe: SessionRecipe, session_scope: str) -> str:
    def helper(scope: str) -> str:
        scope = scope.strip()

        if scope.startswith('.'):
            scope = scope[1:]

        if (not scope.startswith('https://')) and (not scope.startswith('http://')):
            scope = 'http://' + scope

        try:
            url_obj = urlparse(scope)
            scope = url_obj.hostname

            if scope.startswith('.'):
                scope = scope[1:]

            return scope
        except Exception:
            raise_general_exception(
                recipe, 'Please provide a valid sessionScope')

    no_dot_normalised = helper(session_scope)
    if no_dot_normalised == 'localhost' or is_an_ip_address(no_dot_normalised):
        return no_dot_normalised

    if no_dot_normalised.startswith('.'):
        return no_dot_normalised[1:]

    return no_dot_normalised


def normalise_same_site(same_site: str) -> str:
    same_site = same_site.strip()
    same_site = same_site.lower()
    allowed_values = {'strict', 'lax', 'none'}
    if same_site not in allowed_values:
        raise Exception(
            'cookie same site must be one of "strict", "lax", or "none"')
    return same_site


def get_url_scheme(url) -> str:
    url_obj = urlparse(url)
    return url_obj.scheme


def get_top_level_domain_for_same_site_resolution(url: str) -> str:
    url_obj = urlparse(url)
    hostname = url_obj.hostname

    if hostname.startswith('localhost') or is_an_ip_address(hostname):
        return 'localhost'
    parsed_url = extract(hostname)
    if parsed_url == '':
        raise Exception(
            'Please make sure that the apiDomain and websiteDomain have correct values')

    return parsed_url.domain + '.' + parsed_url.suffix


class InputErrorHandlers:
    def __init__(self,
                 on_token_theft_detected: Union[Callable[[BaseRequest, str, str], Awaitable[None]], None] = None,
                 on_unauthorised: Union[Callable[[BaseRequest, str, BaseResponse], Awaitable[None]], None] = None):
        self.on_token_theft_detected = on_token_theft_detected
        self.on_unauthorised = on_unauthorised


class ErrorHandlers:
    def __init__(self, recipe: SessionRecipe, on_token_theft_detected,
                 on_try_refresh_token, on_unauthorised):
        self.__recipe = recipe
        self.__on_token_theft_detected = on_token_theft_detected
        self.__on_try_refresh_token = on_try_refresh_token
        self.__on_unauthorised = on_unauthorised

    async def on_token_theft_detected(self, request: BaseRequest, session_handle: str, user_id: str):
        try:
            response = await self.__on_token_theft_detected(request, session_handle, user_id)
        except TypeError:
            response = self.__on_token_theft_detected(
                request, session_handle, user_id)
        clear_cookies(self.__recipe, response)
        return response

    async def on_try_refresh_token(self, request: BaseRequest, message: str, response: BaseResponse):
        try:
            response = await self.__on_try_refresh_token(request, message, response)
        except TypeError:
            response = await self.__on_try_refresh_token(request, message, response)
        return response

    async def on_unauthorised(self, do_clear_cookies: bool, request: BaseRequest, message: str, response: BaseResponse):
        try:
            await self.__on_unauthorised(request, message, response)
        except TypeError:
            await self.__on_unauthorised(request, message, response)
        if do_clear_cookies:
            clear_cookies(self.__recipe, response)
        return response


async def default_unauthorised_callback(_: BaseRequest, __: str, response: BaseResponse):
    from .recipe import SessionRecipe
    return send_non_200_response('unauthorised', SessionRecipe.get_instance(
    ).config.session_expired_status_code, response)


async def default_try_refresh_token_callback(_: BaseRequest, __: str, response: BaseResponse):
    from .recipe import SessionRecipe
    return send_non_200_response('try refresh token', SessionRecipe.get_instance(
    ).config.session_expired_status_code, response)


async def default_token_theft_detected_callback(_: BaseRequest, session_handle: str, __: str, response: BaseResponse):
    from .recipe import SessionRecipe
    await SessionRecipe.get_instance().recipe_implementation.revoke_session(session_handle)
    return send_non_200_response('token theft detected', SessionRecipe.get_instance(
    ).config.session_expired_status_code, response)


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
        openid_feature: Union[OpenIdInputOverrideConfig, None] = None
    ):
        self.functions = functions
        self.apis = apis
        self.openid_feature = openid_feature


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface],
                                        None] = None, apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        self.functions = functions
        self.apis = apis


class JWTConfig:
    def __init__(self, enable: bool, property_name_in_access_token_payload: Union[str, None] = None, issuer: Union[str, None] = None):
        if property_name_in_access_token_payload is None:
            property_name_in_access_token_payload = 'jwt'
        if property_name_in_access_token_payload == ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY:
            raise Exception(JWT_RESERVED_KEY_USE_ERROR_MESSAGE)
        self.enable = enable
        self.property_name_in_access_token_payload = property_name_in_access_token_payload
        self.issuer = issuer


class SessionConfig:
    def __init__(self,
                 refresh_token_path: NormalisedURLPath,
                 cookie_domain: str,
                 cookie_same_site: str,
                 cookie_secure: str,
                 session_expired_status_code: int,
                 error_handlers: ErrorHandlers,
                 anti_csrf: str,
                 override: OverrideConfig,
                 framework: str,
                 mode: str,
                 jwt: JWTConfig
                 ):
        self.refresh_token_path = refresh_token_path
        self.cookie_domain = cookie_domain
        self.cookie_same_site = cookie_same_site
        self.cookie_secure = cookie_secure
        self.session_expired_status_code = session_expired_status_code
        self.error_handlers = error_handlers
        self.anti_csrf = anti_csrf
        self.override = override
        self.framework = framework
        self.mode = mode
        self.jwt = jwt


def validate_and_normalise_user_input(
    recipe: SessionRecipe, app_info: AppInfo,
    cookie_domain: Union[str, None] = None,
    cookie_secure: Union[str, None] = None,
    cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
    session_expired_status_code: Union[str, None] = None,
    anti_csrf: Union[Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None] = None,
    error_handlers: Union[InputErrorHandlers, None] = None,
    override: Union[InputOverrideConfig, None] = None,
    jwt: Union[JWTConfig, None] = None
):
    cookie_domain = normalise_session_scope(recipe, cookie_domain) if cookie_domain is not None else None
    top_level_api_domain = get_top_level_domain_for_same_site_resolution(
        app_info.api_domain.get_as_string_dangerous())
    top_level_website_domain = get_top_level_domain_for_same_site_resolution(
        app_info.website_domain.get_as_string_dangerous())

    api_domain_scheme = get_url_scheme(app_info.api_domain.get_as_string_dangerous())
    website_domain_scheme = get_url_scheme(app_info.website_domain.get_as_string_dangerous())
    if cookie_same_site is not None:
        cookie_same_site = normalise_same_site(cookie_same_site)
    elif (top_level_api_domain != top_level_website_domain) or (api_domain_scheme != website_domain_scheme):
        cookie_same_site = 'none'
    else:
        cookie_same_site = 'lax'

    cookie_secure = cookie_secure if cookie_secure is not None else app_info.api_domain.get_as_string_dangerous().startswith(
        'https')

    session_expired_status_code = session_expired_status_code if session_expired_status_code is not None else 401
    if anti_csrf is None:
        anti_csrf = 'VIA_CUSTOM_HEADER' if cookie_same_site == 'none' else 'NONE'

    on_token_theft_detected = default_token_theft_detected_callback
    on_try_refresh_token = default_try_refresh_token_callback
    on_unauthorised = default_unauthorised_callback
    if error_handlers is None:
        error_handlers = InputErrorHandlers()
    if error_handlers.on_token_theft_detected is not None:
        on_token_theft_detected = error_handlers.on_token_theft_detected
    if error_handlers.on_unauthorised is not None:
        on_unauthorised = error_handlers.on_unauthorised
    error_handlers = ErrorHandlers(
        recipe,
        on_token_theft_detected,
        on_try_refresh_token,
        on_unauthorised
    )

    if (cookie_same_site == 'none') and \
            not cookie_secure and \
            not (top_level_api_domain == 'localhost' or is_an_ip_address(top_level_api_domain)) and \
            not (top_level_website_domain == 'localhost' or is_an_ip_address(top_level_website_domain)):
        raise_general_exception('Since your API and website domain are different, for sessions to work, please use '
                                'https on your apiDomain and don\'t set cookieSecure to false.')

    if override is None:
        override = InputOverrideConfig()

    if jwt is None:
        jwt = JWTConfig(False)

    return SessionConfig(
        app_info.api_base_path.append(NormalisedURLPath(SESSION_REFRESH)),
        cookie_domain,
        cookie_same_site,
        cookie_secure,
        session_expired_status_code,
        error_handlers,
        anti_csrf,
        OverrideConfig(override.functions, override.apis),
        app_info.framework,
        app_info.mode,
        jwt
    )
