from .api import handle_email_exists_api as handle_email_exists_api, handle_generate_password_reset_token_api as handle_generate_password_reset_token_api, handle_password_reset_api as handle_password_reset_api, handle_sign_in_api as handle_sign_in_api, handle_sign_up_api as handle_sign_up_api
from .api.implementation import APIImplementation as APIImplementation
from .constants import SIGNIN as SIGNIN, SIGNUP as SIGNUP, SIGNUP_EMAIL_EXISTS as SIGNUP_EMAIL_EXISTS, USER_PASSWORD_RESET as USER_PASSWORD_RESET, USER_PASSWORD_RESET_TOKEN as USER_PASSWORD_RESET_TOKEN
from .exceptions import FieldError as FieldError, SuperTokensEmailPasswordError as SuperTokensEmailPasswordError
from .interfaces import APIOptions as APIOptions
from .recipe_implementation import RecipeImplementation as RecipeImplementation
from .utils import InputEmailVerificationConfig as InputEmailVerificationConfig, InputOverrideConfig as InputOverrideConfig, InputResetPasswordUsingTokenFeature as InputResetPasswordUsingTokenFeature, InputSignUpFeature as InputSignUpFeature, validate_and_normalise_user_input as validate_and_normalise_user_input
from supertokens_python.exceptions import SuperTokensError as SuperTokensError, raise_general_exception as raise_general_exception
from supertokens_python.framework.request import BaseRequest as BaseRequest
from supertokens_python.framework.response import BaseResponse as BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.emailverification import EmailVerificationRecipe as EmailVerificationRecipe
from supertokens_python.recipe_module import APIHandled as APIHandled, RecipeModule as RecipeModule
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Dict, List, TypeGuard, Union

class EmailPasswordRecipe(RecipeModule):
    recipe_id: str
    config: Any
    email_verification_recipe: Any
    recipe_implementation: Any
    api_implementation: Any
    def __init__(self, recipe_id: str, app_info: AppInfo, sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ..., email_verification_recipe: Union[EmailVerificationRecipe, None] = ...) -> None: ...
    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> TypeGuard[SuperTokensError]: ...
    def get_apis_handled(self) -> List[APIHandled]: ...
    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse): ...
    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse: ...
    def get_all_cors_headers(self) -> List[str]: ...
    @staticmethod
    def init(sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ...): ...
    @staticmethod
    def get_instance() -> EmailPasswordRecipe: ...
    @staticmethod
    def reset() -> None: ...
    async def get_email_for_user_id(self, user_id: str, user_context: Dict[str, Any]) -> str: ...
