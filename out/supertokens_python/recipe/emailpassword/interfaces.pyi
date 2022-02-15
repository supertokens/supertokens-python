import abc
from ..emailverification.interfaces import RecipeInterface as EmailVerificationRecipeInterface
from .types import FormField as FormField, User as User
from .utils import EmailPasswordConfig as EmailPasswordConfig
from abc import ABC, abstractmethod
from supertokens_python.framework import BaseRequest as BaseRequest, BaseResponse as BaseResponse
from supertokens_python.recipe.session import SessionContainer as SessionContainer
from typing import Any, Dict, List, Union
from typing_extensions import Literal

class SignUpResult(ABC):
    status: Any
    is_ok: bool
    is_email_already_exists_error: bool
    user: Any
    def __init__(self, status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'], user: Union[User, None]) -> None: ...

class SignUpOkResult(SignUpResult):
    is_ok: bool
    is_email_already_exists_error: bool
    def __init__(self, user: User) -> None: ...

class SignUpEmailAlreadyExistsErrorResult(SignUpResult):
    is_ok: bool
    is_email_already_exists_error: bool
    def __init__(self) -> None: ...

class SignInResult(ABC):
    status: Any
    is_ok: bool
    is_wrong_credentials_error: bool
    user: Any
    def __init__(self, status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'], user: Union[User, None]) -> None: ...

class SignInOkResult(SignInResult):
    is_ok: bool
    is_wrong_credentials_error: bool
    def __init__(self, user: User) -> None: ...

class SignInWrongCredentialsErrorResult(SignInResult):
    is_ok: bool
    is_wrong_credentials_error: bool
    def __init__(self) -> None: ...

class CreateResetPasswordResult(ABC):
    status: Any
    is_ok: bool
    is_unknown_user_id_error: bool
    token: Any
    def __init__(self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR'], token: Union[str, None]) -> None: ...

class CreateResetPasswordOkResult(CreateResetPasswordResult):
    is_ok: bool
    is_unknown_user_id_error: bool
    def __init__(self, token: str) -> None: ...

class CreateResetPasswordWrongUserIdErrorResult(CreateResetPasswordResult):
    is_ok: bool
    is_unknown_user_id_error: bool
    def __init__(self) -> None: ...

class ResetPasswordUsingTokenResult(ABC):
    status: Any
    is_ok: bool
    user_id: Any
    is_reset_password_invalid_token_error: bool
    def __init__(self, status: Literal['OK', 'RESET_PASSWORD_INVALID_TOKEN_ERROR'], user_id: Union[None, str] = ...) -> None: ...

class ResetPasswordUsingTokenOkResult(ResetPasswordUsingTokenResult):
    is_ok: bool
    is_reset_password_invalid_token_error: bool
    def __init__(self, user_id: Union[None, str]) -> None: ...

class ResetPasswordUsingTokenWrongUserIdErrorResult(ResetPasswordUsingTokenResult):
    is_ok: bool
    is_reset_password_invalid_token_error: bool
    def __init__(self) -> None: ...

class UpdateEmailOrPasswordResult(ABC):
    status: Any
    is_ok: bool
    is_email_already_exists_error: bool
    is_unknown_user_id_error: bool
    def __init__(self, status: Literal['OK', 'UNKNOWN_USER_ID_ERROR', 'EMAIL_ALREADY_EXISTS_ERROR']) -> None: ...

class UpdateEmailOrPasswordOkResult(UpdateEmailOrPasswordResult):
    is_ok: bool
    is_email_already_exists_error: bool
    is_unknown_user_id_error: bool
    def __init__(self) -> None: ...

class UpdateEmailOrPasswordEmailAlreadyExistsErrorResult(UpdateEmailOrPasswordResult):
    is_ok: bool
    is_email_already_exists_error: bool
    is_unknown_user_id_error: bool
    def __init__(self) -> None: ...

class UpdateEmailOrPasswordUnknownUserIdErrorResult(UpdateEmailOrPasswordResult):
    is_ok: bool
    is_email_already_exists_error: bool
    is_unknown_user_id_error: bool
    def __init__(self) -> None: ...

class RecipeInterface(ABC, metaclass=abc.ABCMeta):
    def __init__(self) -> None: ...
    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]: ...
    @abstractmethod
    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]: ...
    @abstractmethod
    async def create_reset_password_token(self, user_id: str, user_context: Dict[str, Any]) -> CreateResetPasswordResult: ...
    @abstractmethod
    async def reset_password_using_token(self, token: str, new_password: str, user_context: Dict[str, Any]) -> ResetPasswordUsingTokenResult: ...
    @abstractmethod
    async def sign_in(self, email: str, password: str, user_context: Dict[str, Any]) -> SignInResult: ...
    @abstractmethod
    async def sign_up(self, email: str, password: str, user_context: Dict[str, Any]) -> SignUpResult: ...
    @abstractmethod
    async def update_email_or_password(self, user_id: str, email: Union[str, None], password: Union[str, None], user_context: Dict[str, Any]) -> UpdateEmailOrPasswordResult: ...

class APIOptions:
    request: Any
    response: Any
    recipe_id: Any
    config: Any
    recipe_implementation: Any
    email_verification_recipe_implementation: Any
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str, config: EmailPasswordConfig, recipe_implementation: RecipeInterface, email_verification_recipe_implementation: EmailVerificationRecipeInterface) -> None: ...

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

class EmailExistsGetResponse(ABC):
    status: Any
    exists: Any
    def __init__(self, status: Literal['OK'], exists: bool) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class EmailExistsGetOkResponse(EmailExistsGetResponse):
    def __init__(self, exists: bool) -> None: ...

class GeneratePasswordResetTokenPostResponse(ABC):
    status: Any
    def __init__(self, status: Literal['OK']) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class GeneratePasswordResetTokenPostOkResponse(GeneratePasswordResetTokenPostResponse):
    def __init__(self) -> None: ...

class PasswordResetPostResponse(ABC):
    user_id: Any
    status: Any
    def __init__(self, status: Literal['OK', 'RESET_PASSWORD_INVALID_TOKEN_ERROR'], user_id: Union[str, None] = ...) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class PasswordResetPostOkResponse(PasswordResetPostResponse):
    def __init__(self, user_id: Union[str, None]) -> None: ...

class PasswordResetPostInvalidTokenResponse(PasswordResetPostResponse):
    def __init__(self) -> None: ...

class SignInPostResponse(ABC):
    type: str
    is_ok: bool
    is_wrong_credentials_error: bool
    status: Any
    user: Any
    session: Any
    def __init__(self, status: Literal['OK', 'WRONG_CREDENTIALS_ERROR'], user: Union[User, None] = ..., session: Union[SessionContainer, None] = ...) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class SignInPostOkResponse(SignInPostResponse):
    is_ok: bool
    def __init__(self, user: User, session: SessionContainer) -> None: ...

class SignInPostWrongCredentialsErrorResponse(SignInPostResponse):
    is_wrong_credentials_error: bool
    def __init__(self) -> None: ...

class SignUpPostResponse(ABC):
    type: str
    is_ok: bool
    is_email_already_exists_error: bool
    status: Any
    user: Any
    session: Any
    def __init__(self, status: Literal['OK', 'EMAIL_ALREADY_EXISTS_ERROR'], user: Union[User, None] = ..., session: Union[SessionContainer, None] = ...) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class SignUpPostOkResponse(SignUpPostResponse):
    is_ok: bool
    def __init__(self, user: User, session: SessionContainer) -> None: ...

class SignUpPostEmailAlreadyExistsErrorResponse(SignUpPostResponse):
    is_email_already_exists_error: bool
    def __init__(self) -> None: ...

class APIInterface(metaclass=abc.ABCMeta):
    disable_email_exists_get: bool
    disable_generate_password_reset_token_post: bool
    disable_password_reset_post: bool
    disable_sign_in_post: bool
    disable_sign_up_post: bool
    def __init__(self) -> None: ...
    @abstractmethod
    async def email_exists_get(self, email: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse: ...
    @abstractmethod
    async def generate_password_reset_token_post(self, form_fields: List[FormField], api_options: APIOptions, user_context: Dict[str, Any]) -> GeneratePasswordResetTokenPostResponse: ...
    @abstractmethod
    async def password_reset_post(self, form_fields: List[FormField], token: str, api_options: APIOptions, user_context: Dict[str, Any]) -> PasswordResetPostResponse: ...
    @abstractmethod
    async def sign_in_post(self, form_fields: List[FormField], api_options: APIOptions, user_context: Dict[str, Any]) -> SignInPostResponse: ...
    @abstractmethod
    async def sign_up_post(self, form_fields: List[FormField], api_options: APIOptions, user_context: Dict[str, Any]) -> SignUpPostResponse: ...
