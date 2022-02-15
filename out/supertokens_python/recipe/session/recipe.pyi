from .api import handle_refresh_api as handle_refresh_api, handle_signout_api as handle_signout_api
from .api.implementation import APIImplementation as APIImplementation
from .constants import SESSION_REFRESH as SESSION_REFRESH, SIGNOUT as SIGNOUT
from .cookie_and_header import get_cors_allowed_headers as get_cors_allowed_headers
from .exceptions import SuperTokensSessionError as SuperTokensSessionError, TokenTheftError as TokenTheftError, UnauthorisedError as UnauthorisedError
from .interfaces import APIInterface as APIInterface, APIOptions as APIOptions, RecipeInterface as RecipeInterface
from .recipe_implementation import RecipeImplementation as RecipeImplementation
from .utils import InputErrorHandlers as InputErrorHandlers, InputOverrideConfig as InputOverrideConfig, JWTConfig as JWTConfig, validate_and_normalise_user_input as validate_and_normalise_user_input
from supertokens_python.exceptions import SuperTokensError as SuperTokensError, raise_general_exception as raise_general_exception
from supertokens_python.framework import BaseRequest as BaseRequest
from supertokens_python.framework.response import BaseResponse as BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.openid.recipe import OpenIdRecipe as OpenIdRecipe
from supertokens_python.recipe.session.with_jwt import get_recipe_implementation_with_jwt as get_recipe_implementation_with_jwt
from supertokens_python.recipe_module import APIHandled as APIHandled, RecipeModule as RecipeModule
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Dict, List, TypeGuard, Union
from typing_extensions import Literal

class SessionRecipe(RecipeModule):
    recipe_id: str
    openid_recipe: Any
    config: Any
    recipe_implementation: Any
    api_implementation: Any
    def __init__(self, recipe_id: str, app_info: AppInfo, cookie_domain: Union[str, None] = ..., cookie_secure: Union[bool, None] = ..., cookie_same_site: Union[Literal['lax', 'none', 'strict'], None] = ..., session_expired_status_code: Union[int, None] = ..., anti_csrf: Union[Literal['VIA_TOKEN', 'VIA_CUSTOM_HEADER', 'NONE'], None] = ..., error_handlers: Union[InputErrorHandlers, None] = ..., override: Union[InputOverrideConfig, None] = ..., jwt: Union[JWTConfig, None] = ...) -> None: ...
    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> TypeGuard[SuperTokensError]: ...
    def get_apis_handled(self) -> List[APIHandled]: ...
    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse) -> Union[BaseResponse, None]: ...
    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse: ...
    def get_all_cors_headers(self) -> List[str]: ...
    @staticmethod
    def init(cookie_domain: Union[str, None] = ..., cookie_secure: Union[bool, None] = ..., cookie_same_site: Union[Literal['lax', 'none', 'strict'], None] = ..., session_expired_status_code: Union[int, None] = ..., anti_csrf: Union[Literal['VIA_TOKEN', 'VIA_CUSTOM_HEADER', 'NONE'], None] = ..., error_handlers: Union[InputErrorHandlers, None] = ..., override: Union[InputOverrideConfig, None] = ..., jwt: Union[JWTConfig, None] = ...): ...
    @staticmethod
    def get_instance() -> SessionRecipe: ...
    @staticmethod
    def reset() -> None: ...
    async def verify_session(self, request: BaseRequest, anti_csrf_check: Union[bool, None], session_required: bool, user_context: Dict[str, Any]): ...
