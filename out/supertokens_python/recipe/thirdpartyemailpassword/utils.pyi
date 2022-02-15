from ..emailpassword.utils import InputResetPasswordUsingTokenFeature as InputResetPasswordUsingTokenFeature, InputSignUpFeature as InputSignUpFeature
from ..emailverification.types import User as EmailVerificationUser
from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from .recipe import ThirdPartyEmailPasswordRecipe as ThirdPartyEmailPasswordRecipe
from .types import User as User
from supertokens_python.recipe.emailverification.utils import OverrideConfig as EmailVerificationOverrideConfig, ParentRecipeEmailVerificationConfig as ParentRecipeEmailVerificationConfig
from supertokens_python.recipe.thirdparty.provider import Provider as Provider
from typing import Any, Awaitable, Callable, Dict, List, Union

class InputEmailVerificationConfig:
    get_email_verification_url: Any
    create_and_send_custom_email: Any
    def __init__(self, get_email_verification_url: Union[Callable[[User, Any], Awaitable[str]], None] = ..., create_and_send_custom_email: Union[Callable[[User, str, Any], Awaitable[None]], None] = ...) -> None: ...

def email_verification_create_and_send_custom_email(recipe: ThirdPartyEmailPasswordRecipe, create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]]) -> Callable[[EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]]: ...
def email_verification_get_email_verification_url(recipe: ThirdPartyEmailPasswordRecipe, get_email_verification_url: Callable[[User, Any], Awaitable[str]]) -> Callable[[EmailVerificationUser, Any], Awaitable[str]]: ...
def validate_and_normalise_email_verification_config(recipe: ThirdPartyEmailPasswordRecipe, config: Union[InputEmailVerificationConfig, None], override: InputOverrideConfig) -> ParentRecipeEmailVerificationConfig: ...

class InputOverrideConfig:
    functions: Any
    apis: Any
    email_verification_feature: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ..., email_verification_feature: Union[EmailVerificationOverrideConfig, None] = ...) -> None: ...

class OverrideConfig:
    functions: Any
    apis: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ...) -> None: ...

class ThirdPartyEmailPasswordConfig:
    sign_up_feature: Any
    email_verification_feature: Any
    providers: Any
    reset_password_using_token_feature: Any
    override: Any
    def __init__(self, providers: List[Provider], email_verification_feature: ParentRecipeEmailVerificationConfig, sign_up_feature: Union[InputSignUpFeature, None], reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None], override: OverrideConfig) -> None: ...

def validate_and_normalise_user_input(recipe: ThirdPartyEmailPasswordRecipe, sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ..., providers: Union[List[Provider], None] = ...) -> ThirdPartyEmailPasswordConfig: ...
