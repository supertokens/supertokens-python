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

from ..emailverification.interfaces import \
    RecipeInterface as EmailVerificationRecipeInterface

from typing_extensions import Literal

from .provider import Provider

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import AppInfo

    from .types import User
    from .utils import ThirdPartyConfig


class SignInUpResult(ABC):
    def __init__(self, status: Literal['OK', 'FIELD_ERROR'], user: Union[User, None] = None,
                 created_new_user: Union[bool, None] = None, error: Union[str, None] = None):
        self.status: Literal['OK', 'FIELD_ERROR'] = status
        self.is_ok: bool = False
        self.is_field_error: bool = False
        self.user: Union[User, None] = user
        self.created_new_user: Union[bool, None] = created_new_user
        self.error: Union[str, None] = error


class SignInUpOkResult(SignInUpResult):
    def __init__(self, user: User, created_new_user: bool):
        super().__init__('OK', user, created_new_user)
        self.is_ok = True


class SignInUpFieldErrorResult(SignInUpResult):
    def __init__(self, error: str):
        super().__init__('FIELD_ERROR', error=error)
        self.is_field_error = True


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_users_by_email(self, email: str, user_context: Dict[str, Any]) -> List[User]:
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str,
                                          user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool, user_context: Dict[str, Any]) -> SignInUpResult:
        pass


class APIOptions:
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: ThirdPartyConfig, recipe_implementation: RecipeInterface, providers: List[Provider], app_info: AppInfo, email_verification_recipe_implementation: EmailVerificationRecipeInterface):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: ThirdPartyConfig = config
        self.providers: List[Provider] = providers
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info: AppInfo = app_info
        self.email_verification_recipe_implementation: EmailVerificationRecipeInterface = email_verification_recipe_implementation


class SignInUpPostResponse(ABC):
    def __init__(self, status: Literal['OK', 'NO_EMAIL_GIVEN_BY_PROVIDER', 'FIELD_ERROR'], user: Union[User, None] = None,
                 created_new_user: Union[bool, None] = None, auth_code_response: Union[Dict[str, Any], None] = None,
                 error: Union[str, None] = None,
                 session: Union[SessionContainer, None] = None):
        self.type = 'thirdparty'
        self.status: Literal['OK', 'NO_EMAIL_GIVEN_BY_PROVIDER', 'FIELD_ERROR'] = status
        self.is_ok: bool = False
        self.is_no_email_given_by_provider: bool = False
        self.is_field_error: bool = False
        self.user: Union[User, None] = user
        self.created_new_user: Union[bool, None] = created_new_user
        self.error: Union[str, None] = error
        self.auth_code_response: Union[Dict[str, Any], None] = auth_code_response
        self.session: Union[SessionContainer, None] = session

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        pass


class GeneratePasswordResetTokenResponse(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status

    @abstractmethod
    def to_json(self):
        pass


class EmailExistsResponse(ABC):
    def __init__(self, status: Literal['OK'], exists: bool):
        self.status = status
        self.exists = exists

    @abstractmethod
    def to_json(self):
        pass


class PasswordResetResponse(ABC):
    def __init__(self, status: Literal['OK',
                 'RESET_PASSWORD_INVALID_TOKEN_ERROR']):
        self.status = status

    @abstractmethod
    def to_json(self):
        pass


class SignInUpPostOkResponse(SignInUpPostResponse):
    def __init__(self, user: User, created_new_user: bool,
                 auth_code_response: Dict[str, Any],
                 session: SessionContainer):
        super().__init__('OK', user, created_new_user, auth_code_response, session=session)
        self.is_ok = True

    def to_json(self) -> Dict[str, Any]:
        if self.user is None:
            raise Exception("Should never come here")
        return {
            'status': self.status,
            'user': {
                'id': self.user.user_id,
                'email': self.user.email,
                'timeJoined': self.user.time_joined,
                'thirdParty': {
                    'id': self.user.third_party_info.id,
                    'userId': self.user.third_party_info.user_id
                }
            },
            'createdNewUser': self.created_new_user
        }


class SignInUpPostNoEmailGivenByProviderResponse(SignInUpPostResponse):
    def __init__(self):
        super().__init__('NO_EMAIL_GIVEN_BY_PROVIDER')
        self.is_no_email_given_by_provider = True

    def to_json(self):
        return {
            'status': self.status
        }


class SignInUpPostFieldErrorResponse(SignInUpPostResponse):
    def __init__(self, error: str):
        super().__init__('FIELD_ERROR', error=error)
        self.is_field_error = True

    def to_json(self):
        return {
            'status': self.status,
            'error': self.error
        }


class AuthorisationUrlGetResponse(ABC):
    def __init__(self, status: Literal['OK'], url: str):
        self.status = status
        self.url = url

    def to_json(self):
        return {
            'status': self.status,
            'url': self.url
        }


class AuthorisationUrlGetOkResponse(AuthorisationUrlGetResponse):
    def __init__(self, url: str):
        super().__init__('OK', url)


class APIInterface:
    def __init__(self):
        self.disable_sign_in_up_post = False
        self.disable_authorisation_url_get = False
        self.disable_apple_redirect_handler_post = False

    @abstractmethod
    async def authorisation_url_get(self, provider: Provider,
                                    api_options: APIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse:
        pass

    @abstractmethod
    async def sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None], api_options: APIOptions,
                              user_context: Dict[str, Any]) -> SignInUpPostResponse:
        pass

    @abstractmethod
    async def apple_redirect_handler_post(self, code: str, state: str, api_options: APIOptions, user_context: Dict[str, Any]):
        pass
