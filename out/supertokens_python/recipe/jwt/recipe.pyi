from supertokens_python.exceptions import SuperTokensError as SuperTokensError, raise_general_exception as raise_general_exception
from supertokens_python.framework.request import BaseRequest as BaseRequest
from supertokens_python.framework.response import BaseResponse as BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.jwt.api.implementation import APIImplementation as APIImplementation
from supertokens_python.recipe.jwt.api.jwks_get import jwks_get as jwks_get
from supertokens_python.recipe.jwt.constants import GET_JWKS_API as GET_JWKS_API
from supertokens_python.recipe.jwt.exceptions import SuperTokensJWTError as SuperTokensJWTError
from supertokens_python.recipe.jwt.interfaces import APIOptions as APIOptions
from supertokens_python.recipe.jwt.recipe_implementation import RecipeImplementation as RecipeImplementation
from supertokens_python.recipe.jwt.utils import OverrideConfig as OverrideConfig, validate_and_normalise_user_input as validate_and_normalise_user_input
from supertokens_python.recipe_module import APIHandled as APIHandled, RecipeModule as RecipeModule
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, List, TypeGuard, Union

class JWTRecipe(RecipeModule):
    recipe_id: str
    config: Any
    recipe_implementation: Any
    api_implementation: Any
    def __init__(self, recipe_id: str, app_info: AppInfo, jwt_validity_seconds: Union[int, None] = ..., override: Union[OverrideConfig, None] = ...) -> None: ...
    def get_apis_handled(self) -> List[APIHandled]: ...
    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse): ...
    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse): ...
    def get_all_cors_headers(self) -> List[str]: ...
    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> TypeGuard[SuperTokensError]: ...
    @staticmethod
    def init(jwt_validity_seconds: Union[int, None] = ..., override: Union[OverrideConfig, None] = ...): ...
    @staticmethod
    def get_instance() -> JWTRecipe: ...
    @staticmethod
    def reset() -> None: ...
