from .api import handle_email_verify_api as handle_email_verify_api, handle_generate_email_verify_token_api as handle_generate_email_verify_token_api
from .api.implementation import APIImplementation as APIImplementation
from .constants import USER_EMAIL_VERIFY as USER_EMAIL_VERIFY, USER_EMAIL_VERIFY_TOKEN as USER_EMAIL_VERIFY_TOKEN
from .exceptions import SuperTokensEmailVerificationError as SuperTokensEmailVerificationError
from .interfaces import APIOptions as APIOptions
from .recipe_implementation import RecipeImplementation as RecipeImplementation
from .utils import ParentRecipeEmailVerificationConfig as ParentRecipeEmailVerificationConfig, validate_and_normalise_user_input as validate_and_normalise_user_input
from supertokens_python.exceptions import SuperTokensError as SuperTokensError, raise_general_exception as raise_general_exception
from supertokens_python.framework.request import BaseRequest as BaseRequest
from supertokens_python.framework.response import BaseResponse as BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.emailverification.exceptions import EmailVerificationInvalidTokenError as EmailVerificationInvalidTokenError
from supertokens_python.recipe_module import APIHandled as APIHandled, RecipeModule as RecipeModule
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, List, TypeGuard, Union

class EmailVerificationRecipe(RecipeModule):
    recipe_id: str
    config: Any
    recipe_implementation: Any
    api_implementation: Any
    def __init__(self, recipe_id: str, app_info: AppInfo, config: ParentRecipeEmailVerificationConfig) -> None: ...
    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> TypeGuard[SuperTokensError]: ...
    def get_apis_handled(self) -> List[APIHandled]: ...
    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse) -> Union[BaseResponse, None]: ...
    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse: ...
    def get_all_cors_headers(self) -> List[str]: ...
    @staticmethod
    def init(config: ParentRecipeEmailVerificationConfig): ...
    @staticmethod
    def get_instance() -> EmailVerificationRecipe: ...
    @staticmethod
    def reset() -> None: ...
