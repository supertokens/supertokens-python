from . import exceptions as exceptions
from ...recipe_module import RecipeModule
from .interfaces import SessionContainer as SessionContainer
from .recipe import SessionRecipe as SessionRecipe
from .utils import InputErrorHandlers as InputErrorHandlers, InputOverrideConfig as InputOverrideConfig, JWTConfig as JWTConfig
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Callable, Union
from typing_extensions import Literal

def init(cookie_domain: Union[str, None] = ..., cookie_secure: Union[bool, None] = ..., cookie_same_site: Union[Literal['lax', 'none', 'strict'], None] = ..., session_expired_status_code: Union[int, None] = ..., anti_csrf: Union[Literal['VIA_TOKEN', 'VIA_CUSTOM_HEADER', 'NONE'], None] = ..., error_handlers: Union[InputErrorHandlers, None] = ..., override: Union[InputOverrideConfig, None] = ..., jwt: Union[JWTConfig, None] = ...) -> Callable[[AppInfo], RecipeModule]: ...
