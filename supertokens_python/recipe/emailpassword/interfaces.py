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

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.recipe.emailpassword.types import EmailTemplateVars
from ...supertokens import AppInfo

from ...types import APIResponse, GeneralErrorResponse

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer

    from .types import FormField, User
    from .utils import EmailPasswordConfig


class SignUpOkResult:
    def __init__(self, user: User):
        self.user = user


class SignUpEmailAlreadyExistsError:
    pass


class SignInOkResult:
    def __init__(self, user: User):
        self.user = user


class SignInWrongCredentialsError:
    pass


class CreateResetPasswordOkResult:
    def __init__(self, token: str):
        self.token = token


class CreateResetPasswordWrongUserIdError:
    pass


class CreateResetPasswordLinkOkResult:
    def __init__(self, link: str):
        self.link = link


class CreateResetPasswordLinkUnknownUserIdError:
    pass


class SendResetPasswordEmailOkResult:
    pass


class SendResetPasswordEmailUnknownUserIdError:
    pass


class ResetPasswordUsingTokenOkResult:
    def __init__(self, user_id: Union[str, None]):
        self.user_id = user_id


class ResetPasswordUsingTokenInvalidTokenError:
    pass


class UpdateEmailOrPasswordOkResult:
    pass


class UpdateEmailOrPasswordEmailAlreadyExistsError:
    pass


class UpdateEmailOrPasswordUnknownUserIdError:
    pass


class UpdateEmailOrPasswordPasswordPolicyViolationError:
    failure_reason: str

    def __init__(self, failure_reason: str):
        self.failure_reason = failure_reason


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_user_by_email(
        self, email: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        pass

    @abstractmethod
    async def create_reset_password_token(
        self, user_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[CreateResetPasswordOkResult, CreateResetPasswordWrongUserIdError]:
        pass

    @abstractmethod
    async def reset_password_using_token(
        self,
        token: str,
        new_password: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        ResetPasswordUsingTokenOkResult, ResetPasswordUsingTokenInvalidTokenError
    ]:
        pass

    @abstractmethod
    async def sign_in(
        self, email: str, password: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[SignInOkResult, SignInWrongCredentialsError]:
        pass

    @abstractmethod
    async def sign_up(
        self, email: str, password: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[SignUpOkResult, SignUpEmailAlreadyExistsError]:
        pass

    @abstractmethod
    async def update_email_or_password(
        self,
        user_id: str,
        email: Union[str, None],
        password: Union[str, None],
        apply_password_policy: Union[bool, None],
        tenant_id_for_password_policy: str,
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateEmailOrPasswordOkResult,
        UpdateEmailOrPasswordEmailAlreadyExistsError,
        UpdateEmailOrPasswordUnknownUserIdError,
        UpdateEmailOrPasswordPasswordPolicyViolationError,
    ]:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: EmailPasswordConfig,
        recipe_implementation: RecipeInterface,
        app_info: AppInfo,
        email_delivery: EmailDeliveryIngredient[EmailTemplateVars],
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: EmailPasswordConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info = app_info
        self.email_delivery = email_delivery


class EmailExistsGetOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, exists: bool):
        self.exists = exists

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "exists": self.exists}


class GeneratePasswordResetTokenPostOkResult(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class PasswordResetPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, user_id: Union[str, None]):
        self.user_id = user_id

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class PasswordResetPostInvalidTokenResponse(APIResponse):
    status: str = "RESET_PASSWORD_INVALID_TOKEN_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class SignInPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, user: User, session: SessionContainer):
        self.user = user
        self.session = session

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": {
                "id": self.user.user_id,
                "email": self.user.email,
                "timeJoined": self.user.time_joined,
            },
        }


class SignInPostWrongCredentialsError(APIResponse):
    status: str = "WRONG_CREDENTIALS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class SignUpPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, user: User, session: SessionContainer):
        self.user = user
        self.session = session

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": {
                "id": self.user.user_id,
                "email": self.user.email,
                "timeJoined": self.user.time_joined,
            },
        }


class SignUpPostEmailAlreadyExistsError(APIResponse):
    status: str = "EMAIL_ALREADY_EXISTS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class APIInterface:
    def __init__(self):
        self.disable_email_exists_get = False
        self.disable_generate_password_reset_token_post = False
        self.disable_password_reset_post = False
        self.disable_sign_in_post = False
        self.disable_sign_up_post = False

    @abstractmethod
    async def email_exists_get(
        self,
        email: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailExistsGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def generate_password_reset_token_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[GeneratePasswordResetTokenPostOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def password_reset_post(
        self,
        form_fields: List[FormField],
        token: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        PasswordResetPostOkResult,
        PasswordResetPostInvalidTokenResponse,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def sign_in_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInPostOkResult, SignInPostWrongCredentialsError, GeneralErrorResponse
    ]:
        pass

    @abstractmethod
    async def sign_up_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignUpPostOkResult, SignUpPostEmailAlreadyExistsError, GeneralErrorResponse
    ]:
        pass
