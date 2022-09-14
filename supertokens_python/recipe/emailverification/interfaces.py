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
from typing import TYPE_CHECKING, Any, Dict, Union, Callable, Awaitable, Optional

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.types import APIResponse, GeneralErrorResponse
from ..session.interfaces import SessionContainer
from ...supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse

    from .types import User, VerificationEmailTemplateVars
    from .utils import EmailVerificationConfig


class CreateEmailVerificationTokenOkResult:
    def __init__(self, token: str):
        self.token = token


class CreateEmailVerificationTokenEmailAlreadyVerifiedError:
    pass


class VerifyEmailUsingTokenOkResult:
    def __init__(self, user: User):
        self.user = user


class VerifyEmailUsingTokenInvalidTokenError:
    pass


class RevokeEmailVerificationTokensOkResult:
    pass


class UnverifyEmailOkResult:
    pass


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_email_verification_token(
        self, user_id: str, email: str, user_context: Dict[str, Any]
    ) -> Union[
        CreateEmailVerificationTokenOkResult,
        CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    ]:
        pass

    @abstractmethod
    async def verify_email_using_token(
        self, token: str, user_context: Dict[str, Any]
    ) -> Union[VerifyEmailUsingTokenOkResult, VerifyEmailUsingTokenInvalidTokenError]:
        pass

    @abstractmethod
    async def is_email_verified(
        self, user_id: str, email: str, user_context: Dict[str, Any]
    ) -> bool:
        pass

    @abstractmethod
    async def revoke_email_verification_tokens(
        self, user_id: str, email: str, user_context: Dict[str, Any]
    ) -> RevokeEmailVerificationTokensOkResult:
        pass

    @abstractmethod
    async def unverify_email(
        self, user_id: str, email: str, user_context: Dict[str, Any]
    ) -> UnverifyEmailOkResult:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: EmailVerificationConfig,
        recipe_implementation: RecipeInterface,
        app_info: AppInfo,
        email_delivery: EmailDeliveryIngredient[VerificationEmailTemplateVars],
    ):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation
        self.app_info = app_info
        self.email_delivery = email_delivery


class EmailVerifyPostOkResult(APIResponse):
    def __init__(self, user: User):
        self.user = user
        self.status = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": {"id": self.user.user_id, "email": self.user.email},
        }


class EmailVerifyPostInvalidTokenError(APIResponse):
    def __init__(self):
        self.status = "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class IsEmailVerifiedGetOkResult(APIResponse):
    def __init__(self, is_verified: bool):
        self.status = "OK"
        self.is_verified = is_verified

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "isVerified": self.is_verified}


class GenerateEmailVerifyTokenPostOkResult(APIResponse):
    def __init__(self):
        self.status = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError(APIResponse):
    def __init__(self):
        self.status = "EMAIL_ALREADY_VERIFIED_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class APIInterface(ABC):
    def __init__(self):
        self.disable_email_verify_post = False
        self.disable_is_email_verified_get = False
        self.disable_generate_email_verify_token_post = False

    @abstractmethod
    async def email_verify_post(
        self,
        token: str,
        session: Optional[SessionContainer],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        EmailVerifyPostOkResult, EmailVerifyPostInvalidTokenError, GeneralErrorResponse
    ]:
        pass

    @abstractmethod
    async def is_email_verified_get(
        self,
        session: SessionContainer,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[IsEmailVerifiedGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def generate_email_verify_token_post(
        self,
        session: SessionContainer,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        GenerateEmailVerifyTokenPostOkResult,
        GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
        GeneralErrorResponse,
    ]:
        pass


class GetEmailForUserIdOkResult:
    def __init__(self, email: str):
        self.email = email


class EmailDoesNotExistError(Exception):
    pass


class UnknownUserIdError(Exception):
    pass


TypeGetEmailForUserIdFunction = Callable[
    [str, Dict[str, Any]],
    Awaitable[
        Union[GetEmailForUserIdOkResult, EmailDoesNotExistError, UnknownUserIdError]
    ],
]
