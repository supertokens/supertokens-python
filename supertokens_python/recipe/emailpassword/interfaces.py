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
    def __init__(
            self, status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'], user: Union[User, None]):
        self.status = status
        self.is_ok = False
        self.is_email_already_exists_error = False
        self.user = user


class SignUpOkResult(SignUpResult):
    def __init__(self, user: User):
        super().__init__('OK', user)
        self.is_ok = True
        self.is_email_already_exists_error = False


class SignUpEmailAlreadyExistsErrorResult(SignUpResult):
    def __init__(self):
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR', None)
        self.is_ok = False
        self.is_email_already_exists_error = True


class SignInResult(ABC):
    def __init__(
            self, status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'], user: Union[User, None]):
        self.status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'] = status
        self.is_ok = False
        self.is_wrong_credentials_error: boolean = False
        self.user: Union[User, None] = user


class SignInOkResult(SignInResult):
    def __init__(self, user: User):
        super().__init__('OK', user)
        self.is_ok = True
        self.is_wrong_credentials_error = False


class SignInWrongCredentialsErrorResult(SignInResult):
    def __init__(self):
        super().__init__('WRONG_CREDENTIALS_ERROR', None)
        self.is_ok = False
        self.is_wrong_credentials_error = True


class CreateResetPasswordResult(ABC):
    def __init__(
            self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR'], token: Union[str, None]):
        self.status = status
        self.is_ok = False
        self.is_unknown_user_id_error = False
        self.token = token


class CreateResetPasswordOkResult(CreateResetPasswordResult):
    def __init__(self, token: str):
        super().__init__('OK', token)
        self.is_ok = True
        self.is_unknown_user_id_error = False


class CreateResetPasswordWrongUserIdErrorResult(CreateResetPasswordResult):
    def __init__(self):
        super().__init__('UNKNOWN_USER_ID_ERROR', None)
        self.is_ok = False
        self.is_unknown_user_id_error = True


class ResetPasswordUsingTokenResult(ABC):
    def __init__(self, status: Literal['OK',
                 'RESET_PASSWORD_INVALID_TOKEN_ERROR'], user_id: Union[None, str] = None):
        self.status: Literal['OK',
                             'RESET_PASSWORD_INVALID_TOKEN_ERROR'] = status
        self.is_ok: bool = False
        self.user_id: Union[None, str] = user_id
        self.is_reset_password_invalid_token_error: bool = False


class ResetPasswordUsingTokenOkResult(ResetPasswordUsingTokenResult):
    def __init__(self, user_id: Union[None, str]):
        super().__init__('OK', user_id)
        self.is_ok = True
        self.is_reset_password_invalid_token_error = False


class ResetPasswordUsingTokenWrongUserIdErrorResult(
        ResetPasswordUsingTokenResult):
    def __init__(self):
        super().__init__('RESET_PASSWORD_INVALID_TOKEN_ERROR')
        self.is_ok = False
        self.is_reset_password_invalid_token_error = True


class UpdateEmailOrPasswordResult(ABC):
    def __init__(
            self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR', 'EMAIL_ALREADY_EXISTS_ERROR']):
        self.status = status
        self.is_ok = False
        self.is_email_already_exists_error = False
        self.is_unknown_user_id_error = False


class UpdateEmailOrPasswordOkResult(UpdateEmailOrPasswordResult):
    def __init__(self):
        super().__init__('OK')
        self.is_ok = True
        self.is_email_already_exists_error = False
        self.is_unknown_user_id_error = False


class UpdateEmailOrPasswordEmailAlreadyExistsErrorResult(
        UpdateEmailOrPasswordResult):
    def __init__(self):
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR')
        self.is_ok = False
        self.is_email_already_exists_error = True
        self.is_unknown_user_id_error = False


class UpdateEmailOrPasswordUnknownUserIdErrorResult(
        UpdateEmailOrPasswordResult):
    def __init__(self):
        super().__init__('UNKNOWN_USER_ID_ERROR')
        self.is_ok = False
        self.is_email_already_exists_error = False
        self.is_unknown_user_id_error = True


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def create_reset_password_token(self, user_id: str, user_context: Dict[str, Any]) -> CreateResetPasswordResult:
        pass

    @abstractmethod
    async def reset_password_using_token(self, token: str, new_password: str,
                                         user_context: Dict[str, Any]) -> ResetPasswordUsingTokenResult:
        pass

    @abstractmethod
    async def sign_in(self, email: str, password: str, user_context: Dict[str, Any]) -> SignInResult:
        pass

    @abstractmethod
    async def sign_up(self, email: str, password: str, user_context: Dict[str, Any]) -> SignUpResult:
        pass

    @abstractmethod
    async def update_email_or_password(self, user_id: str, email: Union[str, None],
                                       password: Union[str, None], user_context: Dict[str, Any]) -> UpdateEmailOrPasswordResult:
        pass


class APIOptions:
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: EmailPasswordConfig, recipe_implementation: RecipeInterface,
                 email_verification_recipe_implementation: EmailVerificationRecipeInterface):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: EmailPasswordConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.email_verification_recipe_implementation: EmailVerificationRecipeInterface = email_verification_recipe_implementation


class EmailVerifyPostResponse(ABC):
    def __init__(
            self, status: Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'], user: Union[User, None]):
        self.status = status
        self.is_ok = False
        self.is_email_verification_invalid_token_error = False
        self.user = user

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status
        }


class EmailVerifyPostOkResponse(EmailVerifyPostResponse):
    def __init__(self, user: User):
        super().__init__('OK', user)
        self.is_ok = True
        self.is_email_verification_invalid_token_error = False

    def to_json(self) -> Dict[str, Any]:
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
    def __init__(self):
        super().__init__('EMAIL_VERIFICATION_INVALID_TOKEN_ERROR', None)
        self.is_ok = False
        self.is_email_verification_invalid_token_error = True


class IsEmailVerifiedGetResponse(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status
        self.is_ok = False

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status
        }


class IsEmailVerifiedGetOkResponse(IsEmailVerifiedGetResponse):
    def __init__(self, is_verified: bool):
        super().__init__('OK')
        self.is_verified = is_verified
        self.is_ok = True

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'isVerified': self.is_verified
        }


class GenerateEmailVerifyTokenPostResponse(ABC):
    def __init__(self, status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR']):
        self.status = status
        self.is_ok = False
        self.is_email_already_verified_error = False

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status
        }


class GenerateEmailVerifyTokenPostOkResponse(
        GenerateEmailVerifyTokenPostResponse):
    def __init__(self):
        super().__init__('OK')
        self.is_ok = True
        self.is_email_already_verified_error = False


class GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse(
        GenerateEmailVerifyTokenPostResponse):
    def __init__(self):
        super().__init__('EMAIL_ALREADY_VERIFIED_ERROR')
        self.is_ok = False
        self.is_email_already_verified_error = True


class EmailExistsGetResponse(ABC):
    def __init__(self, status: Literal['OK'], exists: bool):
        self.status = status
        self.exists = exists

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'exists': self.exists
        }


class EmailExistsGetOkResponse(EmailExistsGetResponse):
    def __init__(self, exists: bool):
        super().__init__('OK', exists)


class GeneratePasswordResetTokenPostResponse(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status
        }


class GeneratePasswordResetTokenPostOkResponse(
        GeneratePasswordResetTokenPostResponse):
    def __init__(self):
        super().__init__('OK')


class PasswordResetPostResponse(ABC):
    def __init__(self, status: Literal['OK',
                 'RESET_PASSWORD_INVALID_TOKEN_ERROR'], user_id: Union[str, None] = None):
        self.user_id: Union[str, None] = user_id
        self.status: Literal['OK',
                             'RESET_PASSWORD_INVALID_TOKEN_ERROR'] = status

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status
        }


class PasswordResetPostOkResponse(PasswordResetPostResponse):
    def __init__(self, user_id: Union[str, None]):
        super().__init__('OK', user_id)


class PasswordResetPostInvalidTokenResponse(PasswordResetPostResponse):
    def __init__(self):
        super().__init__('RESET_PASSWORD_INVALID_TOKEN_ERROR')


class SignInPostResponse(ABC):
    def __init__(
            self, status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'],
            user: Union[User, None] = None,
            session: Union[SessionContainer, None] = None):
        self.type = 'emailpassword'
        self.is_ok: bool = False
        self.is_wrong_credentials_error: bool = False
        self.status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'] = status
        self.user: Union[User, None] = user
        self.session: Union[SessionContainer, None] = session

    def to_json(self) -> Dict[str, Any]:
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
    def __init__(self, user: User, session: SessionContainer):
        super().__init__('OK', user, session)
        self.is_ok = True


class SignInPostWrongCredentialsErrorResponse(SignInPostResponse):
    def __init__(self):
        super().__init__('WRONG_CREDENTIALS_ERROR')
        self.is_wrong_credentials_error = True


class SignUpPostResponse(ABC):
    def __init__(
            self, status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'],
            user: Union[User, None] = None,
            session: Union[SessionContainer, None] = None):
        self.type = 'emailpassword'
        self.is_ok: bool = False
        self.is_email_already_exists_error: bool = False
        self.status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'] = status
        self.user: Union[User, None] = user
        self.session: Union[SessionContainer, None] = session

    def to_json(self) -> Dict[str, Any]:
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
    def __init__(self, user: User, session: SessionContainer):
        super().__init__('OK', user, session)
        self.is_ok = True


class SignUpPostEmailAlreadyExistsErrorResponse(SignUpPostResponse):
    def __init__(self):
        super().__init__('EMAIL_ALREADY_EXISTS_ERROR')
        self.is_email_already_exists_error = True


class APIInterface:
    def __init__(self):
        self.disable_email_exists_get = False
        self.disable_generate_password_reset_token_post = False
        self.disable_password_reset_post = False
        self.disable_sign_in_post = False
        self.disable_sign_up_post = False

    @abstractmethod
    async def email_exists_get(self, email: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        pass

    @abstractmethod
    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 api_options: APIOptions,
                                                 user_context: Dict[str, Any]) -> GeneratePasswordResetTokenPostResponse:
        pass

    @abstractmethod
    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  api_options: APIOptions, user_context: Dict[str, Any]) -> PasswordResetPostResponse:
        pass

    @abstractmethod
    async def sign_in_post(self, form_fields: List[FormField],
                           api_options: APIOptions,
                           user_context: Dict[str, Any]) -> SignInPostResponse:
        pass

    @abstractmethod
    async def sign_up_post(self, form_fields: List[FormField],
                           api_options: APIOptions,
                           user_context: Dict[str, Any]) -> SignUpPostResponse:
        pass
