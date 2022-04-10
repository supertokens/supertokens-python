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
from typing import TYPE_CHECKING, Any, Dict, Union

from typing_extensions import Literal

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse

    from .types import User
    from .utils import EmailVerificationConfig


class CreateEmailVerificationTokenResult(ABC):
    """CreateEmailVerificationTokenResult.
    """

    def __init__(
            self, status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR'], token: Union[str, None]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR']
            status
        token : Union[str, None]
            token
        """
        self.status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR'] = status
        self.is_ok: bool = False
        self.is_email_already_verified: bool = False
        self.token: Union[str, None] = token


class CreateEmailVerificationTokenOkResult(CreateEmailVerificationTokenResult):
    """CreateEmailVerificationTokenOkResult.
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
        self.is_email_already_verified = False


class CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult(
        CreateEmailVerificationTokenResult):
    """CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_ALREADY_VERIFIED_ERROR', None)
        self.is_ok = False
        self.is_email_already_verified = True


class VerifyEmailUsingTokenResult(ABC):
    """VerifyEmailUsingTokenResult.
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


class VerifyEmailUsingTokenOkResult(VerifyEmailUsingTokenResult):
    """VerifyEmailUsingTokenOkResult.
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


class VerifyEmailUsingTokenInvalidTokenErrorResult(
        VerifyEmailUsingTokenResult):
    """VerifyEmailUsingTokenInvalidTokenErrorResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('EMAIL_VERIFICATION_INVALID_TOKEN_ERROR', None)
        self.is_ok = False
        self.is_email_verification_invalid_token_error = True


class RevokeEmailVerificationTokensResult(ABC):
    """RevokeEmailVerificationTokensResult.
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


class RevokeEmailVerificationTokensOkResult(
        RevokeEmailVerificationTokensResult):
    """RevokeEmailVerificationTokensOkResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')
        self.is_ok = True


class UnverifyEmailResult(ABC):
    """UnverifyEmailResult.
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


class UnverifyEmailOkResult(UnverifyEmailResult):
    """UnverifyEmailOkResult.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__('OK')
        self.is_ok = True


class RecipeInterface(ABC):
    """RecipeInterface.
    """

    def __init__(self):
        """__init__.
        """
        pass

    @abstractmethod
    async def create_email_verification_token(self, user_id: str, email: str, user_context: Dict[str, Any]) -> CreateEmailVerificationTokenResult:
        """create_email_verification_token.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateEmailVerificationTokenResult

        """
        pass

    @abstractmethod
    async def verify_email_using_token(self, token: str, user_context: Dict[str, Any]) -> VerifyEmailUsingTokenResult:
        """verify_email_using_token.

        Parameters
        ----------
        token : str
            token
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        VerifyEmailUsingTokenResult

        """
        pass

    @abstractmethod
    async def is_email_verified(self, user_id: str, email: str, user_context: Dict[str, Any]) -> bool:
        """is_email_verified.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        bool

        """
        pass

    @abstractmethod
    async def revoke_email_verification_tokens(self, user_id: str, email: str, user_context: Dict[str, Any]) -> RevokeEmailVerificationTokensResult:
        """revoke_email_verification_tokens.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        RevokeEmailVerificationTokensResult

        """
        pass

    @abstractmethod
    async def unverify_email(self, user_id: str, email: str, user_context: Dict[str, Any]) -> UnverifyEmailResult:
        """unverify_email.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        UnverifyEmailResult

        """
        pass


class APIOptions:
    """APIOptions.
    """

    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str,
                 config: EmailVerificationConfig, recipe_implementation: RecipeInterface):
        """__init__.

        Parameters
        ----------
        request : BaseRequest
            request
        response : BaseResponse
            response
        recipe_id : str
            recipe_id
        config : EmailVerificationConfig
            config
        recipe_implementation : RecipeInterface
            recipe_implementation
        """
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


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
        self.status: Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'] = status
        self.is_ok: bool = False
        self.is_email_verification_invalid_token_error: bool = False
        self.user: Union[User, None] = user

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


class APIInterface(ABC):
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
        self.disable_email_verify_post = False
        self.disable_is_email_verified_get = False
        self.disable_generate_email_verify_token_post = False

    @abstractmethod
    async def email_verify_post(self, token: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailVerifyPostResponse:
        """email_verify_post.

        Parameters
        ----------
        token : str
            token
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        EmailVerifyPostResponse

        """
        pass

    @abstractmethod
    async def is_email_verified_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> IsEmailVerifiedGetResponse:
        """is_email_verified_get.

        Parameters
        ----------
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        IsEmailVerifiedGetResponse

        """
        pass

    @abstractmethod
    async def generate_email_verify_token_post(self, api_options: APIOptions,
                                               user_context: Dict[str, Any]) -> GenerateEmailVerifyTokenPostResponse:
        """generate_email_verify_token_post.

        Parameters
        ----------
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        GenerateEmailVerifyTokenPostResponse

        """
        pass
