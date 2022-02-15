import abc
from ..emailverification.interfaces import RecipeInterface as EmailVerificationRecipeInterface
from .provider import Provider as Provider
from .types import User as User
from .utils import ThirdPartyConfig as ThirdPartyConfig
from abc import ABC, abstractmethod
from supertokens_python.framework import BaseRequest as BaseRequest, BaseResponse as BaseResponse
from supertokens_python.recipe.session import SessionContainer as SessionContainer
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Dict, List, Union
from typing_extensions import Literal

class SignInUpResult(ABC):
    status: Any
    is_ok: bool
    is_field_error: bool
    user: Any
    created_new_user: Any
    error: Any
    def __init__(self, status: Literal['OK', 'FIELD_ERROR'], user: Union[User, None] = ..., created_new_user: Union[bool, None] = ..., error: Union[str, None] = ...) -> None: ...

class SignInUpOkResult(SignInUpResult):
    is_ok: bool
    def __init__(self, user: User, created_new_user: bool) -> None: ...

class SignInUpFieldErrorResult(SignInUpResult):
    is_field_error: bool
    def __init__(self, error: str) -> None: ...

class RecipeInterface(ABC, metaclass=abc.ABCMeta):
    def __init__(self) -> None: ...
    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]: ...
    @abstractmethod
    async def get_users_by_email(self, email: str, user_context: Dict[str, Any]) -> List[User]: ...
    @abstractmethod
    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str, user_context: Dict[str, Any]) -> Union[User, None]: ...
    @abstractmethod
    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str, email_verified: bool, user_context: Dict[str, Any]) -> SignInUpResult: ...

class APIOptions:
    request: Any
    response: Any
    recipe_id: Any
    config: Any
    providers: Any
    recipe_implementation: Any
    app_info: Any
    email_verification_recipe_implementation: Any
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str, config: ThirdPartyConfig, recipe_implementation: RecipeInterface, providers: List[Provider], app_info: AppInfo, email_verification_recipe_implementation: EmailVerificationRecipeInterface) -> None: ...

class SignInUpPostResponse(ABC, metaclass=abc.ABCMeta):
    type: str
    status: Any
    is_ok: bool
    is_no_email_given_by_provider: bool
    is_field_error: bool
    user: Any
    created_new_user: Any
    error: Any
    auth_code_response: Any
    session: Any
    def __init__(self, status: Literal['OK', 'NO_EMAIL_GIVEN_BY_PROVIDER', 'FIELD_ERROR'], user: Union[User, None] = ..., created_new_user: Union[bool, None] = ..., auth_code_response: Union[Dict[str, Any], None] = ..., error: Union[str, None] = ..., session: Union[SessionContainer, None] = ...) -> None: ...
    @abstractmethod
    def to_json(self) -> Dict[str, Any]: ...

class GeneratePasswordResetTokenResponse(ABC, metaclass=abc.ABCMeta):
    status: Any
    def __init__(self, status: Literal['OK']) -> None: ...
    @abstractmethod
    def to_json(self): ...

class EmailExistsResponse(ABC, metaclass=abc.ABCMeta):
    status: Any
    exists: Any
    def __init__(self, status: Literal['OK'], exists: bool) -> None: ...
    @abstractmethod
    def to_json(self): ...

class PasswordResetResponse(ABC, metaclass=abc.ABCMeta):
    status: Any
    def __init__(self, status: Literal['OK', 'RESET_PASSWORD_INVALID_TOKEN_ERROR']) -> None: ...
    @abstractmethod
    def to_json(self): ...

class SignInUpPostOkResponse(SignInUpPostResponse):
    is_ok: bool
    def __init__(self, user: User, created_new_user: bool, auth_code_response: Dict[str, Any], session: SessionContainer) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class SignInUpPostNoEmailGivenByProviderResponse(SignInUpPostResponse):
    is_no_email_given_by_provider: bool
    def __init__(self) -> None: ...
    def to_json(self): ...

class SignInUpPostFieldErrorResponse(SignInUpPostResponse):
    is_field_error: bool
    def __init__(self, error: str) -> None: ...
    def to_json(self): ...

class AuthorisationUrlGetResponse(ABC):
    status: Any
    url: Any
    def __init__(self, status: Literal['OK'], url: str) -> None: ...
    def to_json(self): ...

class AuthorisationUrlGetOkResponse(AuthorisationUrlGetResponse):
    def __init__(self, url: str) -> None: ...

class APIInterface(metaclass=abc.ABCMeta):
    disable_sign_in_up_post: bool
    disable_authorisation_url_get: bool
    disable_apple_redirect_handler_post: bool
    def __init__(self) -> None: ...
    @abstractmethod
    async def authorisation_url_get(self, provider: Provider, api_options: APIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse: ...
    @abstractmethod
    async def sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None], api_options: APIOptions, user_context: Dict[str, Any]) -> SignInUpPostResponse: ...
    @abstractmethod
    async def apple_redirect_handler_post(self, code: str, state: str, api_options: APIOptions, user_context: Dict[str, Any]): ...
