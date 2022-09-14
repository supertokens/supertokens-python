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
from typing import TYPE_CHECKING, Any, Dict, List, Union

from ...types import APIResponse, GeneralErrorResponse
from .provider import Provider

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import AppInfo

    from .types import User
    from .utils import ThirdPartyConfig


class SignInUpOkResult:
    def __init__(self, user: User, created_new_user: bool):
        self.user = user
        self.created_new_user = created_new_user


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
        self, email: str, user_context: Dict[str, Any]
    ) -> List[User]:
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(
        self,
        third_party_id: str,
        third_party_user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[User, None]:
        pass

    @abstractmethod
    async def sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        user_context: Dict[str, Any],
    ) -> SignInUpOkResult:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: ThirdPartyConfig,
        recipe_implementation: RecipeInterface,
        providers: List[Provider],
        app_info: AppInfo,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: ThirdPartyConfig = config
        self.providers: List[Provider] = providers
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info: AppInfo = app_info


class SignInUpPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(
        self,
        user: User,
        created_new_user: bool,
        auth_code_response: Dict[str, Any],
        session: SessionContainer,
    ):
        self.user = user
        self.created_new_user = created_new_user
        self.auth_code_response = auth_code_response
        self.session = session

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

    def __init__(self, url: str):
        self.url = url

    def to_json(self):
        return {"status": self.status, "url": self.url}


class APIInterface:
    def __init__(self):
        self.disable_sign_in_up_post = False
        self.disable_authorisation_url_get = False
        self.disable_apple_redirect_handler_post = False

    @abstractmethod
    async def authorisation_url_get(
        self, provider: Provider, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> Union[AuthorisationUrlGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def sign_in_up_post(
        self,
        provider: Provider,
        code: str,
        redirect_uri: str,
        client_id: Union[str, None],
        auth_code_response: Union[Dict[str, Any], None],
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
        code: str,
        state: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ):
        pass
