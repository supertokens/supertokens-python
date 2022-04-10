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
from xmlrpc.client import boolean

from ..emailverification.interfaces import \
    RecipeInterface as EmailVerificationRecipeInterface

from typing_extensions import Literal

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer

    from .types import FormField, User
    from .utils import EmailPasswordConfig


class SignUpResult(ABC):
    """SignUpResult.
    """

    def __init__(
            self, status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'], user: Union[User, None]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR']
            status
        user : Union[User, None]
            user
        """
        self.status = status
        self.is_ok = False
        self.is_email_already_exists_error = False
        self.user = user


class SignUpOkResult(SignUpResult):
    """SignUpOkResult.
    """

    def __init__(self, user: User):
        """__init__.

        Parameters
        ----------
        user : User
            user
        """
        super().__init__('OK', user)
        self.is_ok = True
        self.is_email_already_exists_error = False


class SignUpEmailAlreadyExistsErrorResult(SignUpResult):
    """SignUpEmailAlreadyExistsErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR', None)
        self.is_ok = False
        self.is_email_already_exists_error = True


class SignInResult(ABC):
    """SignInResult.
    """

    def __init__(
            self, status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'], user: Union[User, None]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'WRONG_CREDENTIALS_ERROR']
            status
        user : Union[User, None]
            user
        """
        self.status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'] = status
        self.is_ok = False
        self.is_wrong_credentials_error: boolean = False
        self.user: Union[User, None] = user


class SignInOkResult(SignInResult):
    """SignInOkResult.
    """

    def __init__(self, user: User):
        """__init__.

        Parameters
        ----------
        user : User
            user
        """
        super().__init__('OK', user)
        self.is_ok = True
        self.is_wrong_credentials_error = False


class SignInWrongCredentialsErrorResult(SignInResult):
    """SignInWrongCredentialsErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('WRONG_CREDENTIALS_ERROR', None)
        self.is_ok = False
        self.is_wrong_credentials_error = True


class CreateResetPasswordResult(ABC):
    """CreateResetPasswordResult.
    """

    def __init__(
            self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR'], token: Union[str, None]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'UNKNOWN_USER_ID_ERROR']
            status
        token : Union[str, None]
            token
        """
        self.status = status
        self.is_ok = False
        self.is_unknown_user_id_error = False
        self.token = token


class CreateResetPasswordOkResult(CreateResetPasswordResult):
    """CreateResetPasswordOkResult.
    """

    def __init__(self, token: str):
        """__init__.

        Parameters
        ----------
        token : str
            token
        """
        super().__init__('OK', token)
        self.is_ok = True
        self.is_unknown_user_id_error = False


class CreateResetPasswordWrongUserIdErrorResult(CreateResetPasswordResult):
    """CreateResetPasswordWrongUserIdErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('UNKNOWN_USER_ID_ERROR', None)
        self.is_ok = False
        self.is_unknown_user_id_error = True


class ResetPasswordUsingTokenResult(ABC):
    """ResetPasswordUsingTokenResult.
    """

    def __init__(self, status: Literal['OK',
                 'RESET_PASSWORD_INVALID_TOKEN_ERROR'], user_id: Union[None, str] = None):
        """__init__.

        Parameters
        ----------
        status : Literal['OK',
                         'RESET_PASSWORD_INVALID_TOKEN_ERROR']
            status
        user_id : Union[None, str]
            user_id
        """
        self.status: Literal['OK',
                             'RESET_PASSWORD_INVALID_TOKEN_ERROR'] = status
        self.is_ok: bool = False
        self.user_id: Union[None, str] = user_id
        self.is_reset_password_invalid_token_error: bool = False


class ResetPasswordUsingTokenOkResult(ResetPasswordUsingTokenResult):
    """ResetPasswordUsingTokenOkResult.
    """

    def __init__(self, user_id: Union[None, str]):
        """__init__.

        Parameters
        ----------
        user_id : Union[None, str]
            user_id
        """
        super().__init__('OK', user_id)
        self.is_ok = True
        self.is_reset_password_invalid_token_error = False


class ResetPasswordUsingTokenWrongUserIdErrorResult(
        ResetPasswordUsingTokenResult):
    """ResetPasswordUsingTokenWrongUserIdErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('RESET_PASSWORD_INVALID_TOKEN_ERROR')
        self.is_ok = False
        self.is_reset_password_invalid_token_error = True


class UpdateEmailOrPasswordResult(ABC):
    """UpdateEmailOrPasswordResult.
    """

    def __init__(
            self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR', 'EMAIL_ALREADY_EXISTS_ERROR']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'UNKNOWN_USER_ID_ERROR', 'EMAIL_ALREADY_EXISTS_ERROR']
            status
        """
        self.status = status
        self.is_ok = False
        self.is_email_already_exists_error = False
        self.is_unknown_user_id_error = False


class UpdateEmailOrPasswordOkResult(UpdateEmailOrPasswordResult):
    """UpdateEmailOrPasswordOkResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')
        self.is_ok = True
        self.is_email_already_exists_error = False
        self.is_unknown_user_id_error = False


class UpdateEmailOrPasswordEmailAlreadyExistsErrorResult(
        UpdateEmailOrPasswordResult):
    """UpdateEmailOrPasswordEmailAlreadyExistsErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR')
        self.is_ok = False
        self.is_email_already_exists_error = True
        self.is_unknown_user_id_error = False


class UpdateEmailOrPasswordUnknownUserIdErrorResult(
        UpdateEmailOrPasswordResult):
    """UpdateEmailOrPasswordUnknownUserIdErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('UNKNOWN_USER_ID_ERROR')
        self.is_ok = False
        self.is_email_already_exists_error = False
        self.is_unknown_user_id_error = True


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
    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_email.

        Parameters
        ----------
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        pass

    @abstractmethod
    async def create_reset_password_token(self, user_id: str, user_context: Dict[str, Any]) -> CreateResetPasswordResult:
        """create_reset_password_token.

        Parameters
        ----------
        user_id : str
            user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateResetPasswordResult

        """
        pass

    @abstractmethod
    async def reset_password_using_token(self, token: str, new_password: str,
                                         user_context: Dict[str, Any]) -> ResetPasswordUsingTokenResult:
        """reset_password_using_token.

        Parameters
        ----------
        token : str
            token
        new_password : str
            new_password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ResetPasswordUsingTokenResult

        """
        pass

    @abstractmethod
    async def sign_in(self, email: str, password: str, user_context: Dict[str, Any]) -> SignInResult:
        """sign_in.

        Parameters
        ----------
        email : str
            email
        password : str
            password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInResult

        """
        pass

    @abstractmethod
    async def sign_up(self, email: str, password: str, user_context: Dict[str, Any]) -> SignUpResult:
        """sign_up.

        Parameters
        ----------
        email : str
            email
        password : str
            password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignUpResult

        """
        pass

    @abstractmethod
    async def update_email_or_password(self, user_id: str, email: Union[str, None],
                                       password: Union[str, None], user_context: Dict[str, Any]) -> UpdateEmailOrPasswordResult:
        """update_email_or_password.

        Parameters
        ----------
        user_id : str
            user_id
        email : Union[str, None]
            email
        password : Union[str, None]
            password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        UpdateEmailOrPasswordResult

        """
        pass


class APIOptions:
    """APIOptions.
    """

    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: EmailPasswordConfig, recipe_implementation: RecipeInterface,
                 email_verification_recipe_implementation: EmailVerificationRecipeInterface):
        """__init__.

        Parameters
        ----------
        request : BaseRequest
            request
        response : BaseResponse
            response
        recipe_id : str
            recipe_id
        config : EmailPasswordConfig
            config
        recipe_implementation : RecipeInterface
            recipe_implementation
        email_verification_recipe_implementation : EmailVerificationRecipeInterface
            email_verification_recipe_implementation
        """
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: EmailPasswordConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.email_verification_recipe_implementation: EmailVerificationRecipeInterface = email_verification_recipe_implementation


class EmailVerifyPostResponse(ABC):
    """EmailVerifyPostResponse.
    """

    def __init__(
            self, status: Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'], user: Union[User, None]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR']
            status
        user : Union[User, None]
            user
        """
        self.status = status
        self.is_ok = False
        self.is_email_verification_invalid_token_error = False
        self.user = user

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status
        }


class EmailVerifyPostOkResponse(EmailVerifyPostResponse):
    """EmailVerifyPostOkResponse.
    """

    def __init__(self, user: User):
        """__init__.

        Parameters
        ----------
        user : User
            user
        """
        super().__init__('OK', user)
        self.is_ok = True
        self.is_email_verification_invalid_token_error = False

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
                'email': self.user.email
            }
        }


class EmailVerifyPostInvalidTokenErrorResponse(EmailVerifyPostResponse):
    """EmailVerifyPostInvalidTokenErrorResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_VERIFICATION_INVALID_TOKEN_ERROR', None)
        self.is_ok = False
        self.is_email_verification_invalid_token_error = True


class IsEmailVerifiedGetResponse(ABC):
    """IsEmailVerifiedGetResponse.
    """

    def __init__(self, status: Literal['OK']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        """
        self.status = status
        self.is_ok = False

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status
        }


class IsEmailVerifiedGetOkResponse(IsEmailVerifiedGetResponse):
    """IsEmailVerifiedGetOkResponse.
    """

    def __init__(self, is_verified: bool):
        """__init__.

        Parameters
        ----------
        is_verified : bool
            is_verified
        """
        super().__init__('OK')
        self.is_verified = is_verified
        self.is_ok = True

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status,
            'isVerified': self.is_verified
        }


class GenerateEmailVerifyTokenPostResponse(ABC):
    """GenerateEmailVerifyTokenPostResponse.
    """

    def __init__(self, status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR']
            status
        """
        self.status = status
        self.is_ok = False
        self.is_email_already_verified_error = False

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status
        }


class GenerateEmailVerifyTokenPostOkResponse(
        GenerateEmailVerifyTokenPostResponse):
    """GenerateEmailVerifyTokenPostOkResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')
        self.is_ok = True
        self.is_email_already_verified_error = False


class GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse(
        GenerateEmailVerifyTokenPostResponse):
    """GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_ALREADY_VERIFIED_ERROR')
        self.is_ok = False
        self.is_email_already_verified_error = True


class EmailExistsGetResponse(ABC):
    """EmailExistsGetResponse.
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

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status,
            'exists': self.exists
        }


class EmailExistsGetOkResponse(EmailExistsGetResponse):
    """EmailExistsGetOkResponse.
    """

    def __init__(self, exists: bool):
        """__init__.

        Parameters
        ----------
        exists : bool
            exists
        """
        super().__init__('OK', exists)


class GeneratePasswordResetTokenPostResponse(ABC):
    """GeneratePasswordResetTokenPostResponse.
    """

    def __init__(self, status: Literal['OK']):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        """
        self.status = status

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status
        }


class GeneratePasswordResetTokenPostOkResponse(
        GeneratePasswordResetTokenPostResponse):
    """GeneratePasswordResetTokenPostOkResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')


class PasswordResetPostResponse(ABC):
    """PasswordResetPostResponse.
    """

    def __init__(self, status: Literal['OK',
                 'RESET_PASSWORD_INVALID_TOKEN_ERROR'], user_id: Union[str, None] = None):
        """__init__.

        Parameters
        ----------
        status : Literal['OK',
                         'RESET_PASSWORD_INVALID_TOKEN_ERROR']
            status
        user_id : Union[str, None]
            user_id
        """
        self.user_id: Union[str, None] = user_id
        self.status: Literal['OK',
                             'RESET_PASSWORD_INVALID_TOKEN_ERROR'] = status

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status
        }


class PasswordResetPostOkResponse(PasswordResetPostResponse):
    """PasswordResetPostOkResponse.
    """

    def __init__(self, user_id: Union[str, None]):
        """__init__.

        Parameters
        ----------
        user_id : Union[str, None]
            user_id
        """
        super().__init__('OK', user_id)


class PasswordResetPostInvalidTokenResponse(PasswordResetPostResponse):
    """PasswordResetPostInvalidTokenResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('RESET_PASSWORD_INVALID_TOKEN_ERROR')


class SignInPostResponse(ABC):
    """SignInPostResponse.
    """

    def __init__(
            self, status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'],
            user: Union[User, None] = None,
            session: Union[SessionContainer, None] = None):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'WRONG_CREDENTIALS_ERROR']
            status
        user : Union[User, None]
            user
        session : Union[SessionContainer, None]
            session
        """
        self.type = 'emailpassword'
        self.is_ok: bool = False
        self.is_wrong_credentials_error: bool = False
        self.status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'] = status
        self.user: Union[User, None] = user
        self.session: Union[SessionContainer, None] = session

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        response = {
            'status': self.status
        }
        if self.user is not None:
            response = {
                'user': {
                    'id': self.user.user_id,
                    'email': self.user.email,
                    'timeJoined': self.user.time_joined
                },
                **response
            }
        return response


class SignInPostOkResponse(SignInPostResponse):
    """SignInPostOkResponse.
    """

    def __init__(self, user: User, session: SessionContainer):
        """__init__.

        Parameters
        ----------
        user : User
            user
        session : SessionContainer
            session
        """
        super().__init__('OK', user, session)
        self.is_ok = True


class SignInPostWrongCredentialsErrorResponse(SignInPostResponse):
    """SignInPostWrongCredentialsErrorResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('WRONG_CREDENTIALS_ERROR')
        self.is_wrong_credentials_error = True


class SignUpPostResponse(ABC):
    """SignUpPostResponse.
    """

    def __init__(
            self, status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'],
            user: Union[User, None] = None,
            session: Union[SessionContainer, None] = None):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR']
            status
        user : Union[User, None]
            user
        session : Union[SessionContainer, None]
            session
        """
        self.type = 'emailpassword'
        self.is_ok: bool = False
        self.is_email_already_exists_error: bool = False
        self.status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'] = status
        self.user: Union[User, None] = user
        self.session: Union[SessionContainer, None] = session

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        response = {
            'status': self.status
        }
        if self.user is not None:
            response = {
                'user': {
                    'id': self.user.user_id,
                    'email': self.user.email,
                    'timeJoined': self.user.time_joined
                },
                **response
            }
        return response


class SignUpPostOkResponse(SignUpPostResponse):
    """SignUpPostOkResponse.
    """

    def __init__(self, user: User, session: SessionContainer):
        """__init__.

        Parameters
        ----------
        user : User
            user
        session : SessionContainer
            session
        """
        super().__init__('OK', user, session)
        self.is_ok = True


class SignUpPostEmailAlreadyExistsErrorResponse(SignUpPostResponse):
    """SignUpPostEmailAlreadyExistsErrorResponse.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR')
        self.is_email_already_exists_error = True


class APIInterface:
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
        self.disable_email_exists_get = False
        self.disable_generate_password_reset_token_post = False
        self.disable_password_reset_post = False
        self.disable_sign_in_post = False
        self.disable_sign_up_post = False

    @abstractmethod
    async def email_exists_get(self, email: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        """email_exists_get.

        Parameters
        ----------
        email : str
            email
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        EmailExistsGetResponse

        """
        pass

    @abstractmethod
    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 api_options: APIOptions,
                                                 user_context: Dict[str, Any]) -> GeneratePasswordResetTokenPostResponse:
        """generate_password_reset_token_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        GeneratePasswordResetTokenPostResponse

        """
        pass

    @abstractmethod
    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  api_options: APIOptions, user_context: Dict[str, Any]) -> PasswordResetPostResponse:
        """password_reset_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        token : str
            token
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        PasswordResetPostResponse

        """
        pass

    @abstractmethod
    async def sign_in_post(self, form_fields: List[FormField],
                           api_options: APIOptions,
                           user_context: Dict[str, Any]) -> SignInPostResponse:
        """sign_in_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInPostResponse

        """
        pass

    @abstractmethod
    async def sign_up_post(self, form_fields: List[FormField],
                           api_options: APIOptions,
                           user_context: Dict[str, Any]) -> SignUpPostResponse:
        """sign_up_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignUpPostResponse

        """
        pass
