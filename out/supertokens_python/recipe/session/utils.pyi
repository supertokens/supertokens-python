from .constants import SESSION_REFRESH as SESSION_REFRESH
from .cookie_and_header import clear_cookies as clear_cookies
from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from .recipe import SessionRecipe as SessionRecipe
from .with_jwt.constants import ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY as ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY, JWT_RESERVED_KEY_USE_ERROR_MESSAGE as JWT_RESERVED_KEY_USE_ERROR_MESSAGE
from supertokens_python.exceptions import raise_general_exception as raise_general_exception
from supertokens_python.framework import BaseRequest as BaseRequest, BaseResponse as BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.recipe.openid import InputOverrideConfig as OpenIdInputOverrideConfig
from supertokens_python.supertokens import AppInfo as AppInfo
from supertokens_python.utils import is_an_ip_address as is_an_ip_address, send_non_200_response as send_non_200_response
from typing import Any, Awaitable, Callable, Union
from typing_extensions import Literal

def normalise_session_scope(session_scope: str) -> str: ...
def normalise_same_site(same_site: str) -> Literal['strict', 'lax', 'none']: ...
def get_url_scheme(url: str) -> str: ...
def get_top_level_domain_for_same_site_resolution(url: str) -> str: ...

class ErrorHandlers:
    def __init__(self, on_token_theft_detected: Callable[[BaseRequest, str, str, BaseResponse], Union[BaseResponse, Awaitable[BaseResponse]]], on_try_refresh_token: Callable[[BaseRequest, str, BaseResponse], Union[BaseResponse, Awaitable[BaseResponse]]], on_unauthorised: Callable[[BaseRequest, str, BaseResponse], Union[BaseResponse, Awaitable[BaseResponse]]]) -> None: ...
    async def on_token_theft_detected(self, recipe: SessionRecipe, request: BaseRequest, session_handle: str, user_id: str, response: BaseResponse) -> BaseResponse: ...
    async def on_try_refresh_token(self, request: BaseRequest, message: str, response: BaseResponse): ...
    async def on_unauthorised(self, recipe: SessionRecipe, do_clear_cookies: bool, request: BaseRequest, message: str, response: BaseResponse): ...

class InputErrorHandlers(ErrorHandlers):
    def __init__(self, on_token_theft_detected: Union[None, Callable[[BaseRequest, str, str, BaseResponse], Union[BaseResponse, Awaitable[BaseResponse]]]] = ..., on_unauthorised: Union[Callable[[BaseRequest, str, BaseResponse], Union[BaseResponse, Awaitable[BaseResponse]]], None] = ...) -> None: ...

async def default_unauthorised_callback(_: BaseRequest, __: str, response: BaseResponse) -> BaseResponse: ...
async def default_try_refresh_token_callback(_: BaseRequest, __: str, response: BaseResponse) -> BaseResponse: ...
async def default_token_theft_detected_callback(_: BaseRequest, session_handle: str, __: str, response: BaseResponse) -> BaseResponse: ...

class InputOverrideConfig:
    functions: Any
    apis: Any
    openid_feature: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ..., openid_feature: Union[OpenIdInputOverrideConfig, None] = ...) -> None: ...

class OverrideConfig:
    functions: Any
    apis: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ...) -> None: ...

class JWTConfig:
    enable: Any
    property_name_in_access_token_payload: Any
    issuer: Any
    def __init__(self, enable: bool, property_name_in_access_token_payload: Union[str, None] = ..., issuer: Union[str, None] = ...) -> None: ...

class SessionConfig:
    refresh_token_path: Any
    cookie_domain: Any
    cookie_same_site: Any
    cookie_secure: Any
    session_expired_status_code: Any
    error_handlers: Any
    anti_csrf: Any
    override: Any
    framework: Any
    mode: Any
    jwt: Any
    def __init__(self, refresh_token_path: NormalisedURLPath, cookie_domain: Union[None, str], cookie_same_site: Literal['lax', 'strict', 'none'], cookie_secure: bool, session_expired_status_code: int, error_handlers: ErrorHandlers, anti_csrf: str, override: OverrideConfig, framework: str, mode: str, jwt: JWTConfig) -> None: ...

def validate_and_normalise_user_input(app_info: AppInfo, cookie_domain: Union[str, None] = ..., cookie_secure: Union[bool, None] = ..., cookie_same_site: Union[Literal['lax', 'none', 'strict'], None] = ..., session_expired_status_code: Union[int, None] = ..., anti_csrf: Union[Literal['VIA_TOKEN', 'VIA_CUSTOM_HEADER', 'NONE'], None] = ..., error_handlers: Union[ErrorHandlers, None] = ..., override: Union[InputOverrideConfig, None] = ..., jwt: Union[JWTConfig, None] = ...): ...
