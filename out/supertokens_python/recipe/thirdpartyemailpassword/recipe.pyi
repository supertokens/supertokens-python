from ..emailpassword.utils import InputResetPasswordUsingTokenFeature as InputResetPasswordUsingTokenFeature, InputSignUpFeature as InputSignUpFeature
from .api.implementation import APIImplementation as APIImplementation
from .exceptions import SupertokensThirdPartyEmailPasswordError as SupertokensThirdPartyEmailPasswordError
from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from .recipeimplementation.implementation import RecipeImplementation as RecipeImplementation
from .utils import InputEmailVerificationConfig as InputEmailVerificationConfig, InputOverrideConfig as InputOverrideConfig, validate_and_normalise_user_input as validate_and_normalise_user_input
from supertokens_python.exceptions import SuperTokensError as SuperTokensError
from supertokens_python.framework.request import BaseRequest as BaseRequest
from supertokens_python.framework.response import BaseResponse as BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe as EmailPasswordRecipe
from supertokens_python.recipe.emailverification import EmailVerificationRecipe as EmailVerificationRecipe
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe as ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.provider import Provider as Provider
from supertokens_python.recipe.thirdparty.utils import SignInAndUpFeature as SignInAndUpFeature
from supertokens_python.recipe_module import APIHandled as APIHandled, RecipeModule as RecipeModule
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Dict, List, TypeGuard, Union

class ThirdPartyEmailPasswordRecipe(RecipeModule):
    recipe_id: str
    config: Any
    recipe_implementation: Any
    api_implementation: Any
    email_verification_recipe: Any
    email_password_recipe: Any
    third_party_recipe: Any
    def __init__(self, recipe_id: str, app_info: AppInfo, sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ..., providers: Union[List[Provider], None] = ..., email_verification_recipe: Union[EmailVerificationRecipe, None] = ..., email_password_recipe: Union[EmailPasswordRecipe, None] = ..., third_party_recipe: Union[ThirdPartyRecipe, None] = ...): ...
    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> TypeGuard[SuperTokensError]: ...
    def get_apis_handled(self) -> List[APIHandled]: ...
    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse): ...
    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse: ...
    def get_all_cors_headers(self) -> List[str]: ...
    @staticmethod
    def init(sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ..., providers: Union[List[Provider], None] = ...): ...
    @staticmethod
    def get_instance() -> ThirdPartyEmailPasswordRecipe: ...
    @staticmethod
    def reset() -> None: ...
    async def get_email_for_user_id(self, user_id: str, user_context: Dict[str, Any]) -> str: ...
