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
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError

from ...supertokens import AppInfo
from ...types import (
    RecipeUserId,
)
from ...types.response import APIResponse, GeneralErrorResponse

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer

    from ...types import User
    from .types import FormField
    from .utils import EmailPasswordConfig


class SignUpOkResult:
    status: str = "OK"

    def __init__(self, user: User, recipe_user_id: RecipeUserId):
        self.user = user
        self.recipe_user_id = recipe_user_id

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": self.user.to_json(),
            "recipeUserId": self.recipe_user_id.get_as_string(),
        }


class EmailAlreadyExistsError(APIResponse):
    status: str = "EMAIL_ALREADY_EXISTS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class SignInOkResult:
    def __init__(self, user: User, recipe_user_id: RecipeUserId):
        self.user = user
        self.recipe_user_id = recipe_user_id


class WrongCredentialsError(APIResponse):
    status: str = "WRONG_CREDENTIALS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class CreateResetPasswordOkResult:
    def __init__(self, token: str):
        self.token = token


class ConsumePasswordResetTokenOkResult:
    def __init__(self, email: str, user_id: str):
        self.email = email
        self.user_id = user_id

    def to_json(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "userId": self.user_id,
        }


class PasswordResetTokenInvalidError(APIResponse):
    status: str = "RESET_PASSWORD_INVALID_TOKEN_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UpdateEmailOrPasswordOkResult:
    pass


class UnknownUserIdError:
    pass


class UpdateEmailOrPasswordEmailChangeNotAllowedError:
    def __init__(self, reason: str):
        self.reason = reason


class PasswordPolicyViolationError(APIResponse):
    def __init__(self, failure_reason: str):
        self.failure_reason = failure_reason

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": "PASSWORD_POLICY_VIOLATED_ERROR",
            "failureReason": self.failure_reason,
        }


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def sign_up(
        self,
        email: str,
        password: str,
        tenant_id: str,
        session: Union[SessionContainer, None],
        should_try_linking_with_session_user: Union[bool, None],
        user_context: Dict[str, Any],
    ) -> Union[
        SignUpOkResult,
        EmailAlreadyExistsError,
        LinkingToSessionUserFailedError,
    ]:
        pass

    @abstractmethod
    async def create_new_recipe_user(
        self,
        email: str,
        password: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[SignUpOkResult, EmailAlreadyExistsError]:
        pass

    @abstractmethod
    async def sign_in(
        self,
        email: str,
        password: str,
        tenant_id: str,
        session: Union[SessionContainer, None],
        should_try_linking_with_session_user: Union[bool, None],
        user_context: Dict[str, Any],
    ) -> Union[
        SignInOkResult,
        WrongCredentialsError,
        LinkingToSessionUserFailedError,
    ]:
        pass

    @abstractmethod
    async def verify_credentials(
        self,
        email: str,
        password: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[SignInOkResult, WrongCredentialsError]:
        pass

    @abstractmethod
    async def create_reset_password_token(
        self,
        user_id: str,
        email: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[CreateResetPasswordOkResult, UnknownUserIdError]:
        pass

    @abstractmethod
    async def consume_password_reset_token(
        self,
        token: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[ConsumePasswordResetTokenOkResult, PasswordResetTokenInvalidError]:
        pass

    @abstractmethod
    async def update_email_or_password(
        self,
        recipe_user_id: RecipeUserId,
        email: Union[str, None],
        password: Union[str, None],
        apply_password_policy: Union[bool, None],
        tenant_id_for_password_policy: str,
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateEmailOrPasswordOkResult,
        EmailAlreadyExistsError,
        UnknownUserIdError,
        UpdateEmailOrPasswordEmailChangeNotAllowedError,
        PasswordPolicyViolationError,
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


class GeneratePasswordResetTokenPostNotAllowedResponse(APIResponse):
    status: str = "PASSWORD_RESET_NOT_ALLOWED"

    def __init__(self, reason: str):
        self.reason = reason

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "reason": self.reason}


class PasswordResetPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, email: str, user: User):
        self.email = email
        self.user = user

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
            "user": self.user.to_json(),
        }


class SignInPostNotAllowedResponse(APIResponse):
    status: str = "SIGN_IN_NOT_ALLOWED"

    def __init__(self, reason: str):
        self.reason = reason

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "reason": self.reason}


class SignUpPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, user: User, session: SessionContainer):
        self.user = user
        self.session = session

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "user": self.user.to_json()}


class SignUpPostNotAllowedResponse(APIResponse):
    status: str = "SIGN_UP_NOT_ALLOWED"

    def __init__(self, reason: str):
        self.reason = reason

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "reason": self.reason}


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
    ) -> Union[
        GeneratePasswordResetTokenPostOkResult,
        GeneratePasswordResetTokenPostNotAllowedResponse,
        GeneralErrorResponse,
    ]:
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
        PasswordResetTokenInvalidError,
        PasswordPolicyViolationError,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def sign_in_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        session: Union[SessionContainer, None],
        should_try_linking_with_session_user: Union[bool, None],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInPostOkResult,
        WrongCredentialsError,
        SignInPostNotAllowedResponse,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def sign_up_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        session: Union[SessionContainer, None],
        should_try_linking_with_session_user: Union[bool, None],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignUpPostOkResult,
        EmailAlreadyExistsError,
        SignUpPostNotAllowedResponse,
        GeneralErrorResponse,
    ]:
        pass
