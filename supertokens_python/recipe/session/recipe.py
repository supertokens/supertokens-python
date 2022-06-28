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

from os import environ
from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.framework.response import BaseResponse
from typing_extensions import Literal

from .api import handle_refresh_api, handle_signout_api
from .cookie_and_header import get_cors_allowed_headers
from .exceptions import SuperTokensSessionError, TokenTheftError, UnauthorisedError

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.session.with_jwt import (
    get_recipe_implementation_with_jwt,
)
from supertokens_python.recipe_module import APIHandled, RecipeModule

from .api.implementation import APIImplementation
from .constants import SESSION_REFRESH, SIGNOUT
from .interfaces import APIInterface, APIOptions, RecipeInterface
from .recipe_implementation import RecipeImplementation
from .utils import (
    InputErrorHandlers,
    InputOverrideConfig,
    JWTConfig,
    validate_and_normalise_user_input,
)


class SessionRecipe(RecipeModule):
    recipe_id = "session"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        cookie_domain: Union[str, None] = None,
        cookie_secure: Union[bool, None] = None,
        cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
        session_expired_status_code: Union[int, None] = None,
        anti_csrf: Union[
            Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None
        ] = None,
        error_handlers: Union[InputErrorHandlers, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        jwt: Union[JWTConfig, None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.openid_recipe: Union[None, OpenIdRecipe] = None
        self.config = validate_and_normalise_user_input(
            app_info,
            cookie_domain,
            cookie_secure,
            cookie_same_site,
            session_expired_status_code,
            anti_csrf,
            error_handlers,
            override,
            jwt,
        )
        log_debug_message("session init: anti_csrf: %s", self.config.anti_csrf)
        if self.config.cookie_domain is not None:
            log_debug_message(
                "session init: cookie_domain: %s", self.config.cookie_domain
            )
        else:
            log_debug_message("session init: cookie_domain: None")
        log_debug_message(
            "session init: cookie_same_site: %s", self.config.cookie_same_site
        )
        log_debug_message(
            "session init: cookie_secure: %s", str(self.config.cookie_secure)
        )
        log_debug_message(
            "session init: refresh_token_path: %s ",
            self.config.refresh_token_path.get_as_string_dangerous(),
        )
        log_debug_message(
            "session init: session_expired_status_code: %s",
            str(self.config.session_expired_status_code),
        )

        if self.config.jwt.enable:
            openid_feature_override = None
            if override is not None:
                openid_feature_override = override.openid_feature
            self.openid_recipe = OpenIdRecipe(
                recipe_id,
                app_info,
                None,
                self.config.jwt.issuer,
                openid_feature_override,
            )
            recipe_implementation = RecipeImplementation(
                Querier.get_instance(recipe_id), self.config
            )
            recipe_implementation = get_recipe_implementation_with_jwt(
                recipe_implementation,
                self.config,
                self.openid_recipe.recipe_implementation,
            )
        else:
            recipe_implementation = RecipeImplementation(
                Querier.get_instance(recipe_id), self.config
            )
        self.recipe_implementation: RecipeInterface = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )
        api_implementation = APIImplementation()
        self.api_implementation: APIInterface = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensSessionError)
            or (
                self.openid_recipe is not None
                and self.openid_recipe.is_error_from_this_recipe_based_on_instance(err)
            )
        )

    def get_apis_handled(self) -> List[APIHandled]:
        apis_handled = [
            APIHandled(
                NormalisedURLPath(SESSION_REFRESH),
                "post",
                SESSION_REFRESH,
                self.api_implementation.disable_refresh_post,
            ),
            APIHandled(
                NormalisedURLPath(SIGNOUT),
                "post",
                SIGNOUT,
                self.api_implementation.disable_signout_post,
            ),
        ]
        if self.openid_recipe is not None:
            apis_handled = apis_handled + self.openid_recipe.get_apis_handled()

        return apis_handled

    async def handle_api_request(
        self,
        request_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
    ) -> Union[BaseResponse, None]:
        if request_id == SESSION_REFRESH:
            return await handle_refresh_api(
                self.api_implementation,
                APIOptions(
                    request,
                    response,
                    self.recipe_id,
                    self.config,
                    self.recipe_implementation,
                ),
            )
        if request_id == SIGNOUT:
            return await handle_signout_api(
                self.api_implementation,
                APIOptions(
                    request,
                    response,
                    self.recipe_id,
                    self.config,
                    self.recipe_implementation,
                ),
            )
        if self.openid_recipe is not None:
            return await self.openid_recipe.handle_api_request(
                request_id, request, path, method, response
            )
        return None

    async def handle_error(
        self, request: BaseRequest, err: SuperTokensError, response: BaseResponse
    ) -> BaseResponse:
        if isinstance(err, UnauthorisedError):
            log_debug_message("errorHandler: returning UNAUTHORISED")
            return await self.config.error_handlers.on_unauthorised(
                self, err.clear_cookies, request, str(err), response
            )
        if isinstance(err, TokenTheftError):
            log_debug_message("errorHandler: returning TOKEN_THEFT_DETECTED")
            return await self.config.error_handlers.on_token_theft_detected(
                self, request, err.session_handle, err.user_id, response
            )
        log_debug_message("errorHandler: returning TRY_REFRESH_TOKEN")
        return await self.config.error_handlers.on_try_refresh_token(
            request, str(err), response
        )

    def get_all_cors_headers(self) -> List[str]:
        cors_headers = get_cors_allowed_headers()
        if self.openid_recipe is not None:
            cors_headers = cors_headers + self.openid_recipe.get_all_cors_headers()

        return cors_headers

    @staticmethod
    def init(
        cookie_domain: Union[str, None] = None,
        cookie_secure: Union[bool, None] = None,
        cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
        session_expired_status_code: Union[int, None] = None,
        anti_csrf: Union[
            Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None
        ] = None,
        error_handlers: Union[InputErrorHandlers, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        jwt: Union[JWTConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if SessionRecipe.__instance is None:
                SessionRecipe.__instance = SessionRecipe(
                    SessionRecipe.recipe_id,
                    app_info,
                    cookie_domain,
                    cookie_secure,
                    cookie_same_site,
                    session_expired_status_code,
                    anti_csrf,
                    error_handlers,
                    override,
                    jwt,
                )
                return SessionRecipe.__instance
            raise_general_exception(
                "Session recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> SessionRecipe:
        if SessionRecipe.__instance is not None:
            return SessionRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        SessionRecipe.__instance = None

    async def verify_session(
        self,
        request: BaseRequest,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        user_context: Dict[str, Any],
    ):
        return await self.api_implementation.verify_session(
            APIOptions(
                request, None, self.recipe_id, self.config, self.recipe_implementation
            ),
            anti_csrf_check,
            session_required,
            user_context,
        )
