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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from ...types import RecipeUserId, User
from ...types.response import APIResponse, GeneralErrorResponse
from .provider import Provider, ProviderInput, RedirectUriInfo

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError

    from .types import RawUserInfoFromProvider
    from .utils import ThirdPartyConfig


class SignInUpOkResult:
    def __init__(
        self,
        user: User,
        recipe_user_id: RecipeUserId,
        created_new_recipe_user: bool,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
    ):
        self.user = user
        self.created_new_recipe_user = created_new_recipe_user
        self.oauth_tokens = oauth_tokens
        self.raw_user_info_from_provider = raw_user_info_from_provider
        self.recipe_user_id = recipe_user_id


class ManuallyCreateOrUpdateUserOkResult:
    def __init__(
        self,
        user: User,
        recipe_user_id: RecipeUserId,
        created_new_recipe_user: bool,
    ):
        self.user = user
        self.recipe_user_id = recipe_user_id
        self.created_new_recipe_user = created_new_recipe_user


class GetProviderOkResult:
    def __init__(self, provider: Provider):
        self.provider = provider


class SignInUpNotAllowed(APIResponse):
    status: str = "SIGN_IN_UP_NOT_ALLOWED"
    reason: str

    def __init__(self, reason: str):
        self.reason = reason

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "reason": self.reason}


class EmailChangeNotAllowedError:
    def __init__(self, reason: str):
        self.reason = reason


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def manually_create_or_update_user(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        is_verified: bool,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        ManuallyCreateOrUpdateUserOkResult,
        LinkingToSessionUserFailedError,
        SignInUpNotAllowed,
        EmailChangeNotAllowedError,
    ]:
        pass

    @abstractmethod
    async def sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        is_verified: bool,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[SignInUpOkResult, SignInUpNotAllowed, LinkingToSessionUserFailedError]:
        pass

    @abstractmethod
    async def get_provider(
        self,
        third_party_id: str,
        client_type: Optional[str],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Optional[Provider]:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: ThirdPartyConfig,
        recipe_implementation: RecipeInterface,
        providers: List[ProviderInput],
        app_info: AppInfo,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: ThirdPartyConfig = config
        self.providers: List[ProviderInput] = providers
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info: AppInfo = app_info


class SignInUpPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(
        self,
        user: User,
        created_new_recipe_user: bool,
        session: SessionContainer,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
    ):
        self.user = user
        self.created_new_recipe_user = created_new_recipe_user
        self.session = session
        self.oauth_tokens = oauth_tokens
        self.raw_user_info_from_provider = raw_user_info_from_provider

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": self.user.to_json(),
            "createdNewRecipeUser": self.created_new_recipe_user,
        }


class SignInUpPostNoEmailGivenByProviderResponse(APIResponse):
    status: str = "NO_EMAIL_GIVEN_BY_PROVIDER"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class AuthorisationUrlGetOkResult(APIResponse):
    status: str = "OK"

    def __init__(
        self, url_with_query_params: str, pkce_code_verifier: Optional[str] = None
    ):
        self.url_with_query_params = url_with_query_params
        self.pkce_code_verifier = pkce_code_verifier

    def to_json(self):
        return {
            "status": self.status,
            "urlWithQueryParams": self.url_with_query_params,
            "pkceCodeVerifier": self.pkce_code_verifier,
        }


class APIInterface:
    def __init__(self):
        self.disable_sign_in_up_post = False
        self.disable_authorisation_url_get = False
        self.disable_apple_redirect_handler_post = False

    @abstractmethod
    async def authorisation_url_get(
        self,
        provider: Provider,
        redirect_uri_on_provider_dashboard: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[AuthorisationUrlGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def sign_in_up_post(
        self,
        provider: Provider,
        redirect_uri_info: Optional[RedirectUriInfo],
        oauth_tokens: Optional[Dict[str, Any]],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInUpPostOkResult,
        SignInUpPostNoEmailGivenByProviderResponse,
        SignInUpNotAllowed,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def apple_redirect_handler_post(
        self,
        form_post_info: Dict[str, Any],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ):
        pass
