import abc
from .types import User as User
from .utils import EmailVerificationConfig as EmailVerificationConfig
from abc import ABC, abstractmethod
from supertokens_python.framework import BaseRequest as BaseRequest, BaseResponse as BaseResponse
from typing import Any, Dict, Union
from typing_extensions import Literal

class CreateEmailVerificationTokenResult(ABC):
    status: Any
    is_ok: bool
    is_email_already_verified: bool
    token: Any
    def __init__(self, status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR'], token: Union[str, None]) -> None: ...

class CreateEmailVerificationTokenOkResult(CreateEmailVerificationTokenResult):
    is_ok: bool
    is_email_already_verified: bool
    def __init__(self, token: str) -> None: ...

class CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult(CreateEmailVerificationTokenResult):
    is_ok: bool
    is_email_already_verified: bool
    def __init__(self) -> None: ...

class VerifyEmailUsingTokenResult(ABC):
    status: Any
    is_ok: bool
    is_email_verification_invalid_token_error: bool
    user: Any
    def __init__(self, status: Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'], user: Union[User, None]) -> None: ...

class VerifyEmailUsingTokenOkResult(VerifyEmailUsingTokenResult):
    is_ok: bool
    is_email_verification_invalid_token_error: bool
    def __init__(self, user: User) -> None: ...

class VerifyEmailUsingTokenInvalidTokenErrorResult(VerifyEmailUsingTokenResult):
    is_ok: bool
    is_email_verification_invalid_token_error: bool
    def __init__(self) -> None: ...

class RevokeEmailVerificationTokensResult(ABC):
    status: Any
    is_ok: bool
    def __init__(self, status: Literal['OK']) -> None: ...

class RevokeEmailVerificationTokensOkResult(RevokeEmailVerificationTokensResult):
    is_ok: bool
    def __init__(self) -> None: ...

class UnverifyEmailResult(ABC):
    status: Any
    is_ok: bool
    def __init__(self, status: Literal['OK']) -> None: ...

class UnverifyEmailOkResult(UnverifyEmailResult):
    is_ok: bool
    def __init__(self) -> None: ...

class RecipeInterface(ABC, metaclass=abc.ABCMeta):
    def __init__(self) -> None: ...
    @abstractmethod
    async def create_email_verification_token(self, user_id: str, email: str, user_context: Dict[str, Any]) -> CreateEmailVerificationTokenResult: ...
    @abstractmethod
    async def verify_email_using_token(self, token: str, user_context: Dict[str, Any]) -> VerifyEmailUsingTokenResult: ...
    @abstractmethod
    async def is_email_verified(self, user_id: str, email: str, user_context: Dict[str, Any]) -> bool: ...
    @abstractmethod
    async def revoke_email_verification_tokens(self, user_id: str, email: str, user_context: Dict[str, Any]) -> RevokeEmailVerificationTokensResult: ...
    @abstractmethod
    async def unverify_email(self, user_id: str, email: str, user_context: Dict[str, Any]) -> UnverifyEmailResult: ...

class APIOptions:
    request: Any
    response: Any
    recipe_id: Any
    config: Any
    recipe_implementation: Any
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str, config: EmailVerificationConfig, recipe_implementation: RecipeInterface) -> None: ...

class EmailVerifyPostResponse(ABC):
    status: Any
    is_ok: bool
    is_email_verification_invalid_token_error: bool
    user: Any
    def __init__(self, status: Literal['OK', 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'], user: Union[User, None]) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class EmailVerifyPostOkResponse(EmailVerifyPostResponse):
    is_ok: bool
    is_email_verification_invalid_token_error: bool
    def __init__(self, user: User) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class EmailVerifyPostInvalidTokenErrorResponse(EmailVerifyPostResponse):
    is_ok: bool
    is_email_verification_invalid_token_error: bool
    def __init__(self) -> None: ...

class IsEmailVerifiedGetResponse(ABC):
    status: Any
    is_ok: bool
    def __init__(self, status: Literal['OK']) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class IsEmailVerifiedGetOkResponse(IsEmailVerifiedGetResponse):
    is_verified: Any
    is_ok: bool
    def __init__(self, is_verified: bool) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class GenerateEmailVerifyTokenPostResponse(ABC):
    status: Any
    is_ok: bool
    is_email_already_verified_error: bool
    def __init__(self, status: Literal['OK', 'EMAIL_ALREADY_VERIFIED_ERROR']) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class GenerateEmailVerifyTokenPostOkResponse(GenerateEmailVerifyTokenPostResponse):
    is_ok: bool
    is_email_already_verified_error: bool
    def __init__(self) -> None: ...

class GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse(GenerateEmailVerifyTokenPostResponse):
    is_ok: bool
    is_email_already_verified_error: bool
    def __init__(self) -> None: ...

class APIInterface(ABC, metaclass=abc.ABCMeta):
    disable_email_verify_post: bool
    disable_is_email_verified_get: bool
    disable_generate_email_verify_token_post: bool
    def __init__(self) -> None: ...
    @abstractmethod
    async def email_verify_post(self, token: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailVerifyPostResponse: ...
    @abstractmethod
    async def is_email_verified_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> IsEmailVerifiedGetResponse: ...
    @abstractmethod
    async def generate_email_verify_token_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> GenerateEmailVerifyTokenPostResponse: ...
