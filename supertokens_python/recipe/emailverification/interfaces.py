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
from typing import Union, TYPE_CHECKING

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from .utils import EmailVerificationConfig
    from .types import User


class CreateEmailVerificationTokenResult(ABC):
    def __init__(
            self, status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR'], token: Union[str, None]):
        self.status = status
        self.is_ok = False
        self.is_email_already_verified = False
        self.token = token


class CreateEmailVerificationTokenOkResult(CreateEmailVerificationTokenResult):
    def __init__(self, token: str):
        super().__init__('OK', token)
        self.is_ok = True
        self.is_email_already_verified = False


class CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult(CreateEmailVerificationTokenResult):
    def __init__(self):
        super().__init__('EMAIL_ALREADY_VERIFIED_ERROR', None)
        self.is_ok = False
        self.is_email_already_verified = True


class VerifyEmailUsingTokenResult(ABC):
    def __init__(
            self, status: Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'], token: Union[User, None]):
        self.status = status
        self.is_ok = False
        self.is_email_verification_invalid_token_error = False
        self.user = token


class VerifyEmailUsingTokenOkResult(VerifyEmailUsingTokenResult):
    def __init__(self, user: User):
        super().__init__('OK', user)
        self.is_ok = True
        self.is_email_verification_invalid_token_error = False


class VerifyEmailUsingTokenInvalidTokenErrorResult(VerifyEmailUsingTokenResult):
    def __init__(self):
        super().__init__('EMAIL_VERIFICATION_INVALID_TOKEN_ERROR', None)
        self.is_ok = False
        self.is_email_verification_invalid_token_error = True


class RevokeEmailVerificationTokensResult(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status
        self.is_ok = False


class RevokeEmailVerificationTokensOkResult(RevokeEmailVerificationTokensResult):
    def __init__(self):
        super().__init__('OK')
        self.is_ok = True


class UnverifyEmailResult(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status
        self.is_ok = False


class UnverifyEmailOkResult(UnverifyEmailResult):
    def __init__(self):
        super().__init__('OK')
        self.is_ok = True


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_email_verification_token(self, user_id: str, email: str) -> CreateEmailVerificationTokenResult:
        pass

    @abstractmethod
    async def verify_email_using_token(self, token: str) -> VerifyEmailUsingTokenResult:
        pass

    @abstractmethod
    async def is_email_verified(self, user_id: str, email: str) -> bool:
        pass

    @abstractmethod
    async def revoke_email_verification_tokens(self, user_id: str, email: str) -> RevokeEmailVerificationTokensResult:
        pass

    @abstractmethod
    async def unverify_email(self, user_id: str, email: str) -> UnverifyEmailResult:
        pass


class APIOptions:
    def __init__(self, request: BaseRequest, response: Union[BaseResponse, None], recipe_id: str,
                 config: EmailVerificationConfig, recipe_implementation: RecipeInterface):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class EmailVerifyPostResponse(ABC):
    def __init__(
            self, status: Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'], user: Union[User, None]):
        self.status = status
        self.is_ok = False
        self.is_email_verification_invalid_token_error = False
        self.user = user

    def to_json(self):
        return {
            'status': self.status
        }


class EmailVerifyPostOkResponse(EmailVerifyPostResponse):
    def __init__(self, user: User):
        super().__init__('OK', user)
        self.is_ok = True
        self.is_email_verification_invalid_token_error = False

    def to_json(self):
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

    def to_json(self):
        return {
            'status': self.status
        }


class IsEmailVerifiedGetOkResponse(IsEmailVerifiedGetResponse):
    def __init__(self, is_verified: bool):
        super().__init__('OK')
        self.is_verified = is_verified
        self.is_ok = True

    def to_json(self):
        return {
            'status': self.status,
            'isVerified': self.is_verified
        }


class GenerateEmailVerifyTokenPostResponse(ABC):
    def __init__(self, status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR']):
        self.status = status
        self.is_ok = False
        self.is_email_already_verified_error = False

    def to_json(self):
        return {
            'status': self.status
        }


class GenerateEmailVerifyTokenPostOkResponse(GenerateEmailVerifyTokenPostResponse):
    def __init__(self):
        super().__init__('OK')
        self.is_ok = True
        self.is_email_already_verified_error = False


class GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse(GenerateEmailVerifyTokenPostResponse):
    def __init__(self):
        super().__init__('EMAIL_ALREADY_VERIFIED_ERROR')
        self.is_ok = False
        self.is_email_already_verified_error = True


class APIInterface(ABC):
    def __init__(self):
        self.disable_email_verify_post = False
        self.disable_is_email_verified_get = False
        self.disable_generate_email_verify_token_post = False

    @abstractmethod
    async def email_verify_post(self, token: str, api_options: APIOptions) -> EmailVerifyPostResponse:
        pass

    @abstractmethod
    async def is_email_verified_get(self, api_options: APIOptions) -> IsEmailVerifiedGetResponse:
        pass

    @abstractmethod
    async def generate_email_verify_token_post(self, api_options: APIOptions) -> GenerateEmailVerifyTokenPostResponse:
        pass
