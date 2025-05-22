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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Union

from typing_extensions import Literal

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.types import RecipeUserId
from supertokens_python.types.response import APIResponse, GeneralErrorResponse

from ...supertokens import AppInfo
from ..session.interfaces import SessionContainer

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse

    from .types import EmailVerificationUser, VerificationEmailTemplateVars
    from .utils import EmailVerificationConfig


class CreateEmailVerificationTokenOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, token: str):
        self.token = token


class CreateEmailVerificationTokenEmailAlreadyVerifiedError:
    status: Literal["EMAIL_ALREADY_VERIFIED_ERROR"] = "EMAIL_ALREADY_VERIFIED_ERROR"


class CreateEmailVerificationLinkEmailAlreadyVerifiedError:
    status: Literal["EMAIL_ALREADY_VERIFIED_ERROR"] = "EMAIL_ALREADY_VERIFIED_ERROR"


class CreateEmailVerificationLinkOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, link: str):
        self.link = link


class SendEmailVerificationEmailAlreadyVerifiedError:
    status: Literal["EMAIL_ALREADY_VERIFIED_ERROR"] = "EMAIL_ALREADY_VERIFIED_ERROR"


class SendEmailVerificationEmailOkResult:
    status: Literal["OK"] = "OK"


class VerifyEmailUsingTokenOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, user: EmailVerificationUser):
        self.user = user

    def to_json(self) -> Dict[str, Any]:
        return {"user": self.user.to_json(), "status": self.status}


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
        self,
        recipe_user_id: RecipeUserId,
        email: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        CreateEmailVerificationTokenOkResult,
        CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    ]:
        pass

    @abstractmethod
    async def verify_email_using_token(
        self,
        token: str,
        tenant_id: str,
        attempt_account_linking: bool,
        user_context: Dict[str, Any],
    ) -> Union[VerifyEmailUsingTokenOkResult, VerifyEmailUsingTokenInvalidTokenError]:
        pass

    @abstractmethod
    async def is_email_verified(
        self, recipe_user_id: RecipeUserId, email: str, user_context: Dict[str, Any]
    ) -> bool:
        pass

    @abstractmethod
    async def revoke_email_verification_tokens(
        self,
        recipe_user_id: RecipeUserId,
        email: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> RevokeEmailVerificationTokensOkResult:
        pass

    @abstractmethod
    async def unverify_email(
        self, recipe_user_id: RecipeUserId, email: str, user_context: Dict[str, Any]
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
    def __init__(
        self, user: EmailVerificationUser, new_session: Optional[SessionContainer]
    ):
        self.user = user
        self.new_session = new_session
        self.status = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class EmailVerifyPostInvalidTokenError(APIResponse):
    def __init__(self):
        self.status = "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class IsEmailVerifiedGetOkResult(APIResponse):
    def __init__(self, is_verified: bool, new_session: Optional[SessionContainer]):
        self.status = "OK"
        self.is_verified = is_verified
        self.new_session = new_session

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "isVerified": self.is_verified}


class GenerateEmailVerifyTokenPostOkResult(APIResponse):
    def __init__(self):
        self.status = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError(APIResponse):
    def __init__(self, new_session: Optional[SessionContainer]):
        self.status = "EMAIL_ALREADY_VERIFIED_ERROR"
        self.new_session = new_session

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
        tenant_id: str,
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
    [RecipeUserId, Dict[str, Any]],
    Awaitable[
        Union[GetEmailForUserIdOkResult, EmailDoesNotExistError, UnknownUserIdError]
    ],
]
