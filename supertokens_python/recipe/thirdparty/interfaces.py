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

from ...types import APIResponse, GeneralErrorResponse
from .provider import Provider, ProviderInput, RedirectUriInfo

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import AppInfo

    from .types import User, RawUserInfoFromProvider
    from .utils import ThirdPartyConfig


class SignInUpOkResult:
    def __init__(
        self,
        user: User,
        created_new_user: bool,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
    ):
        self.user = user
        self.created_new_user = created_new_user
        self.oauth_tokens = oauth_tokens
        self.raw_user_info_from_provider = raw_user_info_from_provider


class ManuallyCreateOrUpdateUserOkResult:
    def __init__(
        self,
        user: User,
        created_new_user: bool,
    ):
        self.user = user
        self.created_new_user = created_new_user


class GetProviderOkResult:
    def __init__(self, provider: Provider):
        self.provider = provider


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_users_by_email(
        self, email: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> List[User]:
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(
        self,
        third_party_id: str,
        third_party_user_id: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[User, None]:
        pass

    @abstractmethod
    async def manually_create_or_update_user(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> ManuallyCreateOrUpdateUserOkResult:
        pass

    @abstractmethod
    async def sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> SignInUpOkResult:
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
        created_new_user: bool,
        session: SessionContainer,
        oauth_tokens: Dict[str, Any],
        raw_user_info_from_provider: RawUserInfoFromProvider,
    ):
        self.user = user
        self.created_new_user = created_new_user
        self.session = session
        self.oauth_tokens = oauth_tokens
        self.raw_user_info_from_provider = raw_user_info_from_provider

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": {
                "id": self.user.user_id,
                "email": self.user.email,
                "timeJoined": self.user.time_joined,
                "thirdParty": {
                    "id": self.user.third_party_info.id,
                    "userId": self.user.third_party_info.user_id,
                },
            },
            "createdNewUser": self.created_new_user,
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
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInUpPostOkResult,
        SignInUpPostNoEmailGivenByProviderResponse,
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
