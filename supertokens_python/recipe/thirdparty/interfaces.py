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
    """SignInUpResult.
    """

    def __init__(self, status: Literal['OK', 'FIELD_ERROR'], user: Union[User, None] = None,
                 created_new_user: Union[bool, None] = None, error: Union[str, None] = None):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'FIELD_ERROR']
            status
        user : Union[User, None]
            user
        created_new_user : Union[bool, None]
            created_new_user
        error : Union[str, None]
            error
        """
        self.status: Literal['OK', 'FIELD_ERROR'] = status
        self.is_ok: bool = False
        self.is_field_error: bool = False
        self.user: Union[User, None] = user
        self.created_new_user: Union[bool, None] = created_new_user
        self.error: Union[str, None] = error


class SignInUpOkResult(SignInUpResult):
    """SignInUpOkResult.
    """

    def __init__(self, user: User, created_new_user: bool):
        """__init__.

        Parameters
        ----------
        user : User
            user
        created_new_user : bool
            created_new_user
        """
        super().__init__('OK', user, created_new_user)
        self.is_ok = True


class SignInUpFieldErrorResult(SignInUpResult):
    """SignInUpFieldErrorResult.
    """

    def __init__(self, error: str):
        """__init__.

        Parameters
        ----------
        error : str
            error
        """
        super().__init__('FIELD_ERROR', error=error)
        self.is_field_error = True


class RecipeInterface(ABC):
    """RecipeInterface.
    """

    def __init__(self):
        """__init__.
        """
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_id.

        Parameters
        ----------
        user_id : str
            user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        pass

    @abstractmethod
    async def get_users_by_email(self, email: str, user_context: Dict[str, Any]) -> List[User]:
        """get_users_by_email.

        Parameters
        ----------
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        List[User]

        """
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str,
                                          user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_thirdparty_info.

        Parameters
        ----------
        third_party_id : str
            third_party_id
        third_party_user_id : str
            third_party_user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        pass

    @abstractmethod
    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool, user_context: Dict[str, Any]) -> SignInUpResult:
        """sign_in_up.

        Parameters
        ----------
        third_party_id : str
            third_party_id
        third_party_user_id : str
            third_party_user_id
        email : str
            email
        email_verified : bool
            email_verified
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInUpResult

        """
        pass


class APIOptions:
    """APIOptions.
    """

    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: ThirdPartyConfig, recipe_implementation: RecipeInterface, providers: List[Provider], app_info: AppInfo, email_verification_recipe_implementation: EmailVerificationRecipeInterface):
        """__init__.

        Parameters
        ----------
        request : BaseRequest
            request
        response : BaseResponse
            response
        recipe_id : str
            recipe_id
        config : ThirdPartyConfig
            config
        recipe_implementation : RecipeInterface
            recipe_implementation
        providers : List[Provider]
            providers
        app_info : AppInfo
            app_info
        email_verification_recipe_implementation : EmailVerificationRecipeInterface
            email_verification_recipe_implementation
        """
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: ThirdPartyConfig = config
        self.providers: List[Provider] = providers
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info: AppInfo = app_info
        self.email_verification_recipe_implementation: EmailVerificationRecipeInterface = email_verification_recipe_implementation


class SignInUpPostResponse(ABC):
    """SignInUpPostResponse.
    """

    def __init__(self, status: Literal['OK', 'NO_EMAIL_GIVEN_BY_PROVIDER', 'FIELD_ERROR'], user: Union[User, None] = None,
                 created_new_user: Union[bool, None] = None, auth_code_response: Union[Dict[str, Any], None] = None,
                 error: Union[str, None] = None,
                 session: Union[SessionContainer, None] = None):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'NO_EMAIL_GIVEN_BY_PROVIDER', 'FIELD_ERROR']
            status
        user : Union[User, None]
            user
        created_new_user : Union[bool, None]
            created_new_user
        auth_code_response : Union[Dict[str, Any], None]
            auth_code_response
        error : Union[str, None]
            error
        session : Union[SessionContainer, None]
            session
        """
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
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        pass


class GeneratePasswordResetTokenResponse(ABC):
    """GeneratePasswordResetTokenResponse.
    """

    def __init__(self, status: Literal['OK']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        """
        self.status = status

    @abstractmethod
    def to_json(self):
        """to_json.
        """
        pass


class EmailExistsResponse(ABC):
    """EmailExistsResponse.
    """

    def __init__(self, status: Literal['OK'], exists: bool):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        exists : bool
            exists
        """
        self.status = status
        self.exists = exists

    @abstractmethod
    def to_json(self):
        """to_json.
        """
        pass


class PasswordResetResponse(ABC):
    """PasswordResetResponse.
    """

    def __init__(self, status: Literal['OK',
                 'RESET_PASSWORD_INVALID_TOKEN_ERROR']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK',
                         'RESET_PASSWORD_INVALID_TOKEN_ERROR']
            status
        """
        self.status = status

    @abstractmethod
    def to_json(self):
        """to_json.
        """
        pass


class SignInUpPostOkResponse(SignInUpPostResponse):
    """SignInUpPostOkResponse.
    """

    def __init__(self, user: User, created_new_user: bool,
                 auth_code_response: Dict[str, Any],
                 session: SessionContainer):
        """__init__.

        Parameters
        ----------
        user : User
            user
        created_new_user : bool
            created_new_user
        auth_code_response : Dict[str, Any]
            auth_code_response
        session : SessionContainer
            session
        """
        super().__init__('OK', user, created_new_user, auth_code_response, session=session)
        self.is_ok = True

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
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
    """SignInUpPostNoEmailGivenByProviderResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('NO_EMAIL_GIVEN_BY_PROVIDER')
        self.is_no_email_given_by_provider = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status
        }


class SignInUpPostFieldErrorResponse(SignInUpPostResponse):
    """SignInUpPostFieldErrorResponse.
    """

    def __init__(self, error: str):
        """__init__.

        Parameters
        ----------
        error : str
            error
        """
        super().__init__('FIELD_ERROR', error=error)
        self.is_field_error = True

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'error': self.error
        }


class AuthorisationUrlGetResponse(ABC):
    """AuthorisationUrlGetResponse.
    """

    def __init__(self, status: Literal['OK'], url: str):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        url : str
            url
        """
        self.status = status
        self.url = url

    def to_json(self):
        """to_json.
        """
        return {
            'status': self.status,
            'url': self.url
        }


class AuthorisationUrlGetOkResponse(AuthorisationUrlGetResponse):
    """AuthorisationUrlGetOkResponse.
    """

    def __init__(self, url: str):
        """__init__.

        Parameters
        ----------
        url : str
            url
        """
        super().__init__('OK', url)


class APIInterface:
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
        self.disable_sign_in_up_post = False
        self.disable_authorisation_url_get = False
        self.disable_apple_redirect_handler_post = False

    @abstractmethod
    async def authorisation_url_get(self, provider: Provider,
                                    api_options: APIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse:
        """authorisation_url_get.

        Parameters
        ----------
        provider : Provider
            provider
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        AuthorisationUrlGetResponse

        """
        pass

    @abstractmethod
    async def sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None], api_options: APIOptions,
                              user_context: Dict[str, Any]) -> SignInUpPostResponse:
        """sign_in_up_post.

        Parameters
        ----------
        provider : Provider
            provider
        code : str
            code
        redirect_uri : str
            redirect_uri
        client_id : Union[str, None]
            client_id
        auth_code_response : Union[Dict[str, Any], None]
            auth_code_response
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInUpPostResponse

        """
        pass

    @abstractmethod
    async def apple_redirect_handler_post(self, code: str, state: str, api_options: APIOptions, user_context: Dict[str, Any]):
        """apple_redirect_handler_post.

        Parameters
        ----------
        code : str
            code
        state : str
            state
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context
        """
        pass
