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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.recipe.oauth2provider.exceptions import OAuth2ProviderError
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.types import User

from .interfaces import (
    APIInterface,
    APIOptions,
    PayloadBuilderFunction,
    RecipeInterface,
    UserInfoBuilderFunction,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo


from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.oauth2provider.api.implementation import (
    APIImplementation,
)

from .api import (
    auth_get,
    end_session_get,
    end_session_post,
    introspect_token_post,
    login,
    login_info_get,
    logout_post,
    revoke_token_post,
    token_post,
    user_info_get,
)
from .constants import (
    AUTH_PATH,
    END_SESSION_PATH,
    INTROSPECT_TOKEN_PATH,
    LOGIN_INFO_PATH,
    LOGIN_PATH,
    LOGOUT_PATH,
    REVOKE_TOKEN_PATH,
    TOKEN_PATH,
    USER_INFO_PATH,
)
from .utils import (
    InputOverrideConfig,
    OAuth2ProviderConfig,
    validate_and_normalise_user_input,
)


class OAuth2ProviderRecipe(RecipeModule):
    recipe_id = "oauth2provider"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        override: Union[InputOverrideConfig, None] = None,
    ) -> None:
        super().__init__(recipe_id, app_info)
        self.config: OAuth2ProviderConfig = validate_and_normalise_user_input(
            override,
        )

        from .recipe_implementation import RecipeImplementation

        recipe_implementation: RecipeInterface = RecipeImplementation(
            Querier.get_instance(recipe_id),
            app_info,
            self.get_default_access_token_payload,
            self.get_default_id_token_payload,
            self.get_default_user_info_payload,
        )
        self.recipe_implementation: RecipeInterface = (
            self.config.override.functions(recipe_implementation)
            if self.config.override is not None
            and self.config.override.functions is not None
            else recipe_implementation
        )

        api_implementation = APIImplementation()
        self.api_implementation: APIInterface = (
            self.config.override.apis(api_implementation)
            if self.config.override is not None
            and self.config.override.apis is not None
            else api_implementation
        )

        self._access_token_builders: List[PayloadBuilderFunction] = []
        self._id_token_builders: List[PayloadBuilderFunction] = []
        self._user_info_builders: List[UserInfoBuilderFunction] = []

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, OAuth2ProviderError)

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                NormalisedURLPath(LOGIN_PATH),
                "get",
                LOGIN_PATH,
                self.api_implementation.disable_login_get,
            ),
            APIHandled(
                NormalisedURLPath(TOKEN_PATH),
                "post",
                TOKEN_PATH,
                self.api_implementation.disable_token_post,
            ),
            APIHandled(
                NormalisedURLPath(AUTH_PATH),
                "get",
                AUTH_PATH,
                self.api_implementation.disable_auth_get,
            ),
            APIHandled(
                NormalisedURLPath(LOGIN_INFO_PATH),
                "get",
                LOGIN_INFO_PATH,
                self.api_implementation.disable_login_info_get,
            ),
            APIHandled(
                NormalisedURLPath(USER_INFO_PATH),
                "get",
                USER_INFO_PATH,
                self.api_implementation.disable_user_info_get,
            ),
            APIHandled(
                NormalisedURLPath(REVOKE_TOKEN_PATH),
                "post",
                REVOKE_TOKEN_PATH,
                self.api_implementation.disable_revoke_token_post,
            ),
            APIHandled(
                NormalisedURLPath(INTROSPECT_TOKEN_PATH),
                "post",
                INTROSPECT_TOKEN_PATH,
                self.api_implementation.disable_introspect_token_post,
            ),
            APIHandled(
                NormalisedURLPath(END_SESSION_PATH),
                "get",
                END_SESSION_PATH,
                self.api_implementation.disable_end_session_get,
            ),
            APIHandled(
                NormalisedURLPath(END_SESSION_PATH),
                "post",
                END_SESSION_PATH,
                self.api_implementation.disable_end_session_post,
            ),
            APIHandled(
                NormalisedURLPath(LOGOUT_PATH),
                "post",
                LOGOUT_PATH,
                self.api_implementation.disable_logout_post,
            ),
        ]

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Union[BaseResponse, None]:
        api_options = APIOptions(
            app_info=self.app_info,
            request=request,
            response=response,
            recipe_id=self.recipe_id,
            config=self.config,
            recipe_implementation=self.recipe_implementation,
        )
        if request_id == LOGIN_PATH:
            return await login(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == TOKEN_PATH:
            return await token_post(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == AUTH_PATH:
            return await auth_get(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == LOGIN_INFO_PATH:
            return await login_info_get(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == USER_INFO_PATH:
            return await user_info_get(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == REVOKE_TOKEN_PATH:
            return await revoke_token_post(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == INTROSPECT_TOKEN_PATH:
            return await introspect_token_post(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == END_SESSION_PATH and method == "get":
            return await end_session_get(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == END_SESSION_PATH and method == "post":
            return await end_session_post(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == LOGOUT_PATH and method == "post":
            return await logout_post(
                tenant_id, self.api_implementation, api_options, user_context
            )

        raise Exception(
            "Should never come here: handle_api_request called with unknown id"
        )

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(
        override: Union[InputOverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if OAuth2ProviderRecipe.__instance is None:
                OAuth2ProviderRecipe.__instance = OAuth2ProviderRecipe(
                    OAuth2ProviderRecipe.recipe_id,
                    app_info,
                    override,
                )

                return OAuth2ProviderRecipe.__instance
            raise_general_exception(
                "OAuth2Provider recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> OAuth2ProviderRecipe:
        if OAuth2ProviderRecipe.__instance is not None:
            return OAuth2ProviderRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def get_instance_optional() -> Optional[OAuth2ProviderRecipe]:
        return OAuth2ProviderRecipe.__instance

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        OAuth2ProviderRecipe.__instance = None

    def add_user_info_builder_from_other_recipe(
        self, user_info_builder_fn: UserInfoBuilderFunction
    ) -> None:
        self._user_info_builders.append(user_info_builder_fn)

    def add_access_token_builder_from_other_recipe(
        self, access_token_builder: PayloadBuilderFunction
    ) -> None:
        self._access_token_builders.append(access_token_builder)

    def add_id_token_builder_from_other_recipe(
        self, id_token_builder: PayloadBuilderFunction
    ) -> None:
        self._id_token_builders.append(id_token_builder)

    async def get_default_access_token_payload(
        self,
        user: User,
        scopes: List[str],
        session_handle: str,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}

        if "email" in scopes:
            payload["email"] = user.emails[0] if user.emails else None
            payload["email_verified"] = (
                any(
                    lm.has_same_email_as(user.emails[0]) and lm.verified
                    for lm in user.login_methods
                )
                if user.emails
                else False
            )
            payload["emails"] = user.emails

        if "phoneNumber" in scopes:
            if user.phone_numbers:
                payload["phoneNumber"] = user.phone_numbers[0]
            payload["phoneNumber_verified"] = (
                any(
                    lm.has_same_phone_number_as(user.phone_numbers[0]) and lm.verified
                    for lm in user.login_methods
                )
                if user.phone_numbers
                else False
            )
            payload["phoneNumbers"] = user.phone_numbers

        for fn in self._access_token_builders:
            builder_payload = await fn(user, scopes, session_handle, user_context)
            payload.update(builder_payload)

        return payload

    async def get_default_id_token_payload(
        self,
        user: User,
        scopes: List[str],
        session_handle: str,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}

        if "email" in scopes:
            payload["email"] = user.emails[0] if user.emails else None
            payload["email_verified"] = (
                any(
                    lm.has_same_email_as(user.emails[0]) and lm.verified
                    for lm in user.login_methods
                )
                if user.emails
                else False
            )
            payload["emails"] = user.emails

        if "phoneNumber" in scopes:
            if user.phone_numbers:
                payload["phoneNumber"] = user.phone_numbers[0]
            payload["phoneNumber_verified"] = (
                any(
                    lm.has_same_phone_number_as(user.phone_numbers[0]) and lm.verified
                    for lm in user.login_methods
                )
                if user.phone_numbers
                else False
            )
            payload["phoneNumbers"] = user.phone_numbers

        for fn in self._id_token_builders:
            builder_payload = await fn(user, scopes, session_handle, user_context)
            payload.update(builder_payload)

        return payload

    async def get_default_user_info_payload(
        self,
        user: User,
        access_token_payload: Dict[str, Any],
        scopes: List[str],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"sub": access_token_payload["sub"]}

        if "email" in scopes:
            payload["email"] = user.emails[0] if user.emails else None
            payload["email_verified"] = (
                any(
                    lm.has_same_email_as(user.emails[0]) and lm.verified
                    for lm in user.login_methods
                )
                if user.emails
                else False
            )
            payload["emails"] = user.emails

        if "phoneNumber" in scopes:
            payload["phoneNumber"] = (
                user.phone_numbers[0] if user.phone_numbers else None
            )
            payload["phoneNumber_verified"] = (
                any(
                    lm.has_same_phone_number_as(user.phone_numbers[0]) and lm.verified
                    for lm in user.login_methods
                )
                if user.phone_numbers
                else False
            )
            payload["phoneNumbers"] = user.phone_numbers

        for fn in self._user_info_builders:
            builder_payload = await fn(
                user, access_token_payload, scopes, tenant_id, user_context
            )
            payload.update(builder_payload)

        return payload
