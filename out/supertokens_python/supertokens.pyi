from .constants import FDI_KEY_HEADER as FDI_KEY_HEADER, RID_KEY_HEADER as RID_KEY_HEADER, TELEMETRY as TELEMETRY, TELEMETRY_SUPERTOKENS_API_URL as TELEMETRY_SUPERTOKENS_API_URL, TELEMETRY_SUPERTOKENS_API_VERSION as TELEMETRY_SUPERTOKENS_API_VERSION, USERS as USERS, USER_COUNT as USER_COUNT, USER_DELETE as USER_DELETE
from .exceptions import BadInputError as BadInputError, GeneralError as GeneralError, raise_general_exception as raise_general_exception
from .normalised_url_domain import NormalisedURLDomain as NormalisedURLDomain
from .normalised_url_path import NormalisedURLPath as NormalisedURLPath
from .querier import Querier as Querier
from .recipe.session import SessionRecipe as SessionRecipe
from .recipe.session.cookie_and_header import attach_access_token_to_cookie as attach_access_token_to_cookie, attach_anti_csrf_header as attach_anti_csrf_header, attach_id_refresh_token_to_cookie_and_header as attach_id_refresh_token_to_cookie_and_header, attach_refresh_token_to_cookie as attach_refresh_token_to_cookie, clear_cookies as clear_cookies, set_front_token_in_headers as set_front_token_in_headers
from .recipe_module import RecipeModule as RecipeModule
from .types import ThirdPartyInfo as ThirdPartyInfo, User as User, UsersResponse as UsersResponse
from .utils import compare_version as compare_version, get_rid_from_request as get_rid_from_request, normalise_http_method as normalise_http_method, send_non_200_response as send_non_200_response
from supertokens_python.framework.request import BaseRequest as BaseRequest
from supertokens_python.framework.response import BaseResponse as BaseResponse
from supertokens_python.recipe.session import SessionContainer as SessionContainer
from typing import Any, Callable, List, Union
from typing_extensions import Literal

class SupertokensConfig:
    connection_uri: Any
    api_key: Any
    def __init__(self, connection_uri: str, api_key: Union[str, None] = ...) -> None: ...

class Host:
    domain: Any
    base_path: Any
    def __init__(self, domain: NormalisedURLDomain, base_path: NormalisedURLPath) -> None: ...

class InputAppInfo:
    app_name: Any
    api_gateway_path: Any
    api_domain: Any
    website_domain: Any
    api_base_path: Any
    website_base_path: Any
    def __init__(self, app_name: str, api_domain: str, website_domain: str, api_gateway_path: str = ..., api_base_path: str = ..., website_base_path: str = ...) -> None: ...

class AppInfo:
    app_name: Any
    api_gateway_path: Any
    api_domain: Any
    website_domain: Any
    api_base_path: Any
    website_base_path: Any
    mode: Any
    framework: Any
    def __init__(self, app_name: str, api_domain: str, website_domain: str, framework: Literal['fastapi', 'flask', 'django'], api_gateway_path: str, api_base_path: str, website_base_path: str, mode: Union[Literal['asgi', 'wsgi'], None]) -> None: ...

def manage_cookies_post_response(session: SessionContainer, response: BaseResponse): ...

class Supertokens:
    app_info: Any
    recipe_modules: Any
    def __init__(self, app_info: InputAppInfo, framework: Literal['fastapi', 'flask', 'django'], supertokens_config: SupertokensConfig, recipe_list: List[Callable[[AppInfo], RecipeModule]], mode: Union[Literal['asgi', 'wsgi'], None], telemetry: Union[bool, None]): ...
    async def send_telemetry(self) -> None: ...
    @staticmethod
    def init(app_info: InputAppInfo, framework: Literal['fastapi', 'flask', 'django'], supertokens_config: SupertokensConfig, recipe_list: List[Callable[[AppInfo], RecipeModule]], mode: Union[Literal['asgi', 'wsgi'], None], telemetry: Union[bool, None]): ...
    @staticmethod
    def reset() -> None: ...
    @staticmethod
    def get_instance() -> Supertokens: ...
    def get_all_cors_headers(self) -> List[str]: ...
    async def get_user_count(self, include_recipe_ids: Union[None, List[str]]) -> int: ...
    async def delete_user(self, user_id: str) -> None: ...
    async def get_users(self, time_joined_order: Literal['ASC', 'DESC'], limit: Union[int, None], pagination_token: Union[str, None], include_recipe_ids: Union[None, List[str]]) -> UsersResponse: ...
    async def middleware(self, request: BaseRequest, response: BaseResponse) -> Union[BaseResponse, None]: ...
    async def handle_supertokens_error(self, request: BaseRequest, err: Exception, response: BaseResponse): ...
