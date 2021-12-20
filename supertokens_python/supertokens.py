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

from typing import Union, List, TYPE_CHECKING, Callable

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

from .constants import (
    TELEMETRY,
    RID_KEY_HEADER,
    FDI_KEY_HEADER,
    TELEMETRY_SUPERTOKENS_API_URL,
    TELEMETRY_SUPERTOKENS_API_VERSION, USER_COUNT, USERS
)
from .normalised_url_domain import NormalisedURLDomain
from .normalised_url_path import NormalisedURLPath
from .querier import Querier
from .recipe.session.cookie_and_header import attach_access_token_to_cookie, clear_cookies, \
    attach_refresh_token_to_cookie, attach_id_refresh_token_to_cookie_and_header, attach_anti_csrf_header, \
    set_front_token_in_headers

from .types import UsersResponse, User, ThirdPartyInfo
from .utils import (
    normalise_http_method,
    get_rid_from_request,
    send_non_200_response
)

if TYPE_CHECKING:
    from .recipe_module import RecipeModule
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.recipe.session import Session
from os import environ
from httpx import AsyncClient
from .exceptions import raise_general_exception
from .exceptions import (
    SuperTokensError,
    GeneralError,
    BadInputError
)
from supertokens_python.recipe.session import SessionRecipe
import asyncio


class SupertokensConfig:
    def __init__(self, connection_uri: str, api_key: Union[str, None] = None):
        self.connection_uri = connection_uri
        self.api_key = api_key


class InputAppInfo:
    def __init__(self,
                 app_name: str,
                 api_domain: str,
                 website_domain: str,
                 api_gateway_path: str = '',
                 api_base_path: str = '/auth',
                 website_base_path: str = '/auth',
                 ):
        self.app_name = app_name
        self.api_gateway_path = api_gateway_path
        self.api_domain = api_domain
        self.website_domain = website_domain
        self.api_base_path = api_base_path
        self.website_base_path = website_base_path


class AppInfo:
    def __init__(self, app_name: str, api_domain: str, website_domain: str,
                 framework: Literal['fastapi', 'flask', 'django'], api_gateway_path: str = '',
                 api_base_path: str = '/auth', website_base_path: str = '/auth',
                 mode: Union[Literal['asgi', 'wsgi'], None] = None):
        self.app_name = app_name
        self.api_gateway_path: NormalisedURLPath = NormalisedURLPath(api_gateway_path)
        self.api_domain: NormalisedURLDomain = NormalisedURLDomain(api_domain)
        self.website_domain: NormalisedURLDomain = NormalisedURLDomain(website_domain)
        self.api_base_path: NormalisedURLPath = self.api_gateway_path.append(NormalisedURLPath(api_base_path))
        self.website_base_path: NormalisedURLPath = NormalisedURLPath(website_base_path)
        if mode is not None:
            mode = mode
        elif framework == 'fastapi':
            mode = 'asgi'
        else:
            mode = 'wsgi'
        self.framework = framework
        self.mode = mode


def manage_cookies_post_response(session: Session, response: BaseResponse):
    recipe = SessionRecipe.get_instance()
    if session['remove_cookies']:
        clear_cookies(recipe, response)
    else:
        access_token = session['new_access_token_info']
        if access_token is not None:
            attach_access_token_to_cookie(
                recipe,
                response,
                access_token['token'],
                access_token['expiry']
            )
            set_front_token_in_headers(
                recipe,
                response,
                session['user_id'],
                access_token['expiry'],
                session['access_token_payload']
            )
        refresh_token = session['new_refresh_token_info']
        if refresh_token is not None:
            attach_refresh_token_to_cookie(
                recipe,
                response,
                refresh_token['token'],
                refresh_token['expiry']
            )
        id_refresh_token = session['new_id_refresh_token_info']
        if id_refresh_token is not None:
            attach_id_refresh_token_to_cookie_and_header(
                recipe,
                response,
                id_refresh_token['token'],
                id_refresh_token['expiry']
            )
        anti_csrf_token = session['new_anti_csrf_token']
        if anti_csrf_token is not None:
            attach_anti_csrf_header(recipe, response, anti_csrf_token)


class Supertokens:
    __instance = None

    def __init__(self,
                 app_info: InputAppInfo,
                 framework: Literal['fastapi', 'flask', 'django'],
                 supertokens_config: SupertokensConfig,
                 recipe_list: List[Callable[[AppInfo], RecipeModule]],
                 mode: Union[Literal['asgi', 'wsgi'], None] = None,
                 telemetry: Union[bool, None] = None
                 ):
        self.app_info = AppInfo(
            app_info.app_name,
            app_info.api_domain,
            app_info.website_domain,
            framework,
            app_info.api_gateway_path,
            app_info.api_base_path,
            app_info.website_base_path,
            mode
        )
        hosts = list(map(lambda h: NormalisedURLDomain(h.strip()),
                         filter(lambda x: x != '', supertokens_config.connection_uri.split(';'))))
        Querier.init(hosts, supertokens_config.api_key)

        if len(recipe_list) == 0:
            raise_general_exception(
                None, 'Please provide at least one recipe to the supertokens.init function call')

        self.recipe_modules: List[RecipeModule] = list(map(lambda func: func(self.app_info), recipe_list))

        if telemetry is None:
            telemetry = ('SUPERTOKENS_ENV' not in environ) or (environ['SUPERTOKENS_ENV'] != 'testing')

        if telemetry:
            if self.app_info.framework.lower() == 'flask' or self.app_info.framework.lower() == 'django':
                loop = asyncio.get_event_loop()
                loop.run_until_complete(self.send_telemetry())
            else:
                asyncio.create_task(self.send_telemetry())

    async def send_telemetry(self):
        try:
            querier = Querier.get_instance(None)
            response = await querier.send_get_request(NormalisedURLPath(TELEMETRY), {})
            telemetry_id = None
            if 'exists' in response and response['exists'] and 'telemetry_id' in response:
                telemetry_id = response['telemetry_id']
            data = {
                'appName': self.app_info.app_name,
                'websiteDomain': self.app_info.website_domain.get_as_string_dangerous(),
                'sdk': 'python'
            }
            if telemetry_id is not None:
                data = {
                    **data,
                    'telemetryId': telemetry_id
                }
            async with AsyncClient() as client:
                await client.post(url=TELEMETRY_SUPERTOKENS_API_URL, json=data,
                                  headers={'api-version': TELEMETRY_SUPERTOKENS_API_VERSION})
        except Exception:
            pass

    @staticmethod
    def init(app_info: InputAppInfo,
             framework: Literal['fastapi', 'flask', 'django'],
             supertokens_config: SupertokensConfig,
             recipe_list: List[Callable[[AppInfo], RecipeModule]],
             mode: Union[Literal['asgi', 'wsgi'], None] = None,
             telemetry: Union[bool, None] = None):
        if Supertokens.__instance is None:
            Supertokens.__instance = Supertokens(app_info, framework, supertokens_config, recipe_list, mode, telemetry)

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                None, 'calling testing function in non testing env')
        Querier.reset()
        Supertokens.__instance = None

    @staticmethod
    def get_instance() -> Supertokens:
        if Supertokens.__instance is not None:
            return Supertokens.__instance
        raise_general_exception(
            None,
            'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    def get_all_cors_headers(self) -> List[str]:
        headers_set = set()
        headers_set.add(RID_KEY_HEADER)
        headers_set.add(FDI_KEY_HEADER)
        for recipe in self.recipe_modules:
            headers = recipe.get_all_cors_headers()
            for header in headers:
                headers_set.add(header)

        return list(headers_set)

    async def get_user_count(self, include_recipe_ids: List[str] = None) -> int:
        querier = Querier.get_instance(None)
        include_recipe_ids_str = None
        if include_recipe_ids is not None:
            include_recipe_ids_str = ','.join(include_recipe_ids)

        response = await querier.send_get_request(NormalisedURLPath(USER_COUNT), {
            "includeRecipeIds": include_recipe_ids_str
        })

        return int(response['count'])

    async def get_users(self, time_joined_order: Literal['ASC', 'DESC'],
                        limit: Union[int, None] = None, pagination_token: Union[str, None] = None,
                        include_recipe_ids: List[str] = None) -> UsersResponse:
        querier = Querier.get_instance(None)
        params = {
            'timeJoinedOrder': time_joined_order
        }
        if limit is not None:
            params = {
                'limit': limit,
                **params
            }
        if pagination_token is not None:
            params = {
                'paginationToken': pagination_token,
                **params
            }

        include_recipe_ids_str = None
        if include_recipe_ids is not None:
            include_recipe_ids_str = ','.join(include_recipe_ids)

        params = {
            'paginationToken': include_recipe_ids_str,
            **params
        }

        response = await querier.send_get_request(NormalisedURLPath(USERS), params)
        next_pagination_token = None
        if 'nextPaginationToken' in response:
            next_pagination_token = response['nextPaginationToken']
        users_list = response['users']
        users = []
        for user in users_list:
            recipe_id = user['recipeId']
            user_obj = user['user']
            third_party = None
            if 'thirdParty' in user_obj:
                third_party = ThirdPartyInfo(
                    user_obj['thirdParty']['userId'],
                    user_obj['thirdParty']['id']
                )
            users.append(User(recipe_id, user_obj['id'], user_obj['email'], user_obj['timeJoined'], third_party))

        return UsersResponse(users, next_pagination_token)

    async def middleware(self, request: BaseRequest, response: BaseResponse) -> Union[BaseResponse, None]:
        path = Supertokens.get_instance().app_info.api_gateway_path.append(
            NormalisedURLPath(
                request.get_path()))
        method = normalise_http_method(request.method())

        if not path.startswith(
                Supertokens.get_instance().app_info.api_base_path):
            return None
        else:
            request_rid = get_rid_from_request(request)
            if request_rid is not None and request_rid == 'anti-csrf':
                # see https://github.com/supertokens/supertokens-python/issues/54
                request_rid = None
            request_id = None
            matched_recipe = None
            if request_rid is not None:
                for recipe in Supertokens.get_instance().recipe_modules:
                    if recipe.get_recipe_id() == request_rid:
                        matched_recipe = recipe
                        break
                if matched_recipe is not None:
                    request_id = matched_recipe.return_api_id_if_can_handle_request(
                        path, method)
            else:
                for recipe in Supertokens.get_instance().recipe_modules:
                    request_id = recipe.return_api_id_if_can_handle_request(
                        path, method)
                    if request_id is not None:
                        matched_recipe = recipe
                        break
            if request_id is not None and matched_recipe is not None:
                response = await matched_recipe.handle_api_request(request_id, request, path, method, response)
            else:
                return None

        return response

    async def handle_supertokens_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse):
        if isinstance(err, GeneralError):
            raise err

        if isinstance(err, BadInputError):
            return send_non_200_response(str(err), 400, response)

        for recipe in self.recipe_modules:
            if recipe.is_error_from_this_recipe_based_on_instance(
                    err):
                return await recipe.handle_error(request, err, response)
        raise err
