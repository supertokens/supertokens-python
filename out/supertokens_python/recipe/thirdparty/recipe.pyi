from .api import handle_apple_redirect_api as handle_apple_redirect_api, handle_authorisation_url_api as handle_authorisation_url_api, handle_sign_in_up_api as handle_sign_in_up_api
from .api.implementation import APIImplementation as APIImplementation
from .constants import APPLE_REDIRECT_HANDLER as APPLE_REDIRECT_HANDLER, AUTHORISATIONURL as AUTHORISATIONURL, SIGNINUP as SIGNINUP
from .exceptions import SuperTokensThirdPartyError as SuperTokensThirdPartyError
from .interfaces import APIInterface as APIInterface, APIOptions as APIOptions, RecipeInterface as RecipeInterface
from .recipe_implementation import RecipeImplementation as RecipeImplementation
from .utils import InputEmailVerificationConfig as InputEmailVerificationConfig, InputOverrideConfig as InputOverrideConfig, SignInAndUpFeature as SignInAndUpFeature, validate_and_normalise_user_input as validate_and_normalise_user_input
from supertokens_python.exceptions import SuperTokensError as SuperTokensError, raise_general_exception as raise_general_exception
from supertokens_python.framework.request import BaseRequest as BaseRequest
from supertokens_python.framework.response import BaseResponse as BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.emailverification import EmailVerificationRecipe as EmailVerificationRecipe
from supertokens_python.recipe_module import APIHandled as APIHandled, RecipeModule as RecipeModule
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Dict, List, TypeGuard, Union

class ThirdPartyRecipe(RecipeModule):
    recipe_id: str
    config: Any
    email_verification_recipe: Any
    providers: Any
    recipe_implementation: Any
    api_implementation: Any
    def __init__(self, recipe_id: str, app_info: AppInfo, sign_in_and_up_feature: SignInAndUpFeature, email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ..., email_verification_recipe: Union[EmailVerificationRecipe, None] = ...) -> None: ...
    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> TypeGuard[SuperTokensError]: ...
    def get_apis_handled(self) -> List[APIHandled]: ...
    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse): ...
    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse: ...
    def get_all_cors_headers(self) -> List[str]: ...
    @staticmethod
    def init(sign_in_and_up_feature: SignInAndUpFeature, email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ...): ...
    @staticmethod
    def get_instance() -> ThirdPartyRecipe: ...
    @staticmethod
    def reset() -> None: ...
    async def get_email_for_user_id(self, user_id: str, user_context: Dict[str, Any]) -> str: ...
