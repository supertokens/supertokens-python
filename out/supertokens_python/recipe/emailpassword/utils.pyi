from ..emailverification.types import User as EmailVerificationUser
from ..emailverification.utils import ParentRecipeEmailVerificationConfig as ParentRecipeEmailVerificationConfig
from .constants import FORM_FIELD_EMAIL_ID as FORM_FIELD_EMAIL_ID, FORM_FIELD_PASSWORD_ID as FORM_FIELD_PASSWORD_ID, RESET_PASSWORD as RESET_PASSWORD
from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from .recipe import EmailPasswordRecipe as EmailPasswordRecipe
from .types import InputFormField as InputFormField, NormalisedFormField as NormalisedFormField, User as User
from supertokens_python.recipe.emailverification.utils import OverrideConfig as EmailVerificationOverrideConfig
from supertokens_python.supertokens import AppInfo as AppInfo
from supertokens_python.utils import get_filtered_list as get_filtered_list
from typing import Any, Awaitable, Callable, Dict, List, Union

async def default_validator(_: str) -> Union[str, None]: ...
async def default_password_validator(value: str) -> Union[str, None]: ...
async def default_email_validator(value: str) -> Union[str, None]: ...
def default_get_reset_password_url(app_info: AppInfo) -> Callable[[User, Dict[str, Any]], Awaitable[str]]: ...
def default_create_and_send_custom_email(app_info: AppInfo) -> Callable[[User, str, Dict[str, Any]], Awaitable[None]]: ...

class InputSignUpFeature:
    form_fields: Any
    def __init__(self, form_fields: Union[List[InputFormField], None] = ...) -> None: ...

class SignUpFeature:
    form_fields: Any
    def __init__(self, form_fields: List[NormalisedFormField]) -> None: ...

def normalise_sign_up_form_fields(form_fields: List[InputFormField]) -> List[NormalisedFormField]: ...

class SignInFeature:
    form_fields: Any
    def __init__(self, form_fields: List[NormalisedFormField]) -> None: ...

def normalise_sign_in_form_fields(form_fields: List[NormalisedFormField]) -> List[NormalisedFormField]: ...
def validate_and_normalise_sign_in_config(sign_up_config: SignUpFeature) -> SignInFeature: ...

class InputResetPasswordUsingTokenFeature:
    get_reset_password_url: Any
    create_and_send_custom_email: Any
    def __init__(self, get_reset_password_url: Union[Callable[[User, Dict[str, Any]], Awaitable[str]], None] = ..., create_and_send_custom_email: Union[Callable[[User, str, Dict[str, Any]], Awaitable[None]], None] = ...) -> None: ...

class ResetPasswordUsingTokenFeature:
    form_fields_for_password_reset_form: Any
    form_fields_for_generate_token_form: Any
    get_reset_password_url: Any
    create_and_send_custom_email: Any
    def __init__(self, form_fields_for_password_reset_form: List[NormalisedFormField], form_fields_for_generate_token_form: List[NormalisedFormField], get_reset_password_url: Callable[[User, Dict[str, Any]], Awaitable[str]], create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]]) -> None: ...

class InputEmailVerificationConfig:
    get_email_verification_url: Any
    create_and_send_custom_email: Any
    def __init__(self, get_email_verification_url: Union[Callable[[User, Dict[str, Any]], Awaitable[str]], None] = ..., create_and_send_custom_email: Union[Callable[[User, str, Dict[str, Any]], Awaitable[None]], None] = ...) -> None: ...

def validate_and_normalise_reset_password_using_token_config(app_info: AppInfo, sign_up_config: InputSignUpFeature, config: InputResetPasswordUsingTokenFeature) -> ResetPasswordUsingTokenFeature: ...
def email_verification_create_and_send_custom_email(recipe: EmailPasswordRecipe, create_and_send_custom_email: Callable[[User, str, Dict[str, Any]], Awaitable[None]]) -> Callable[[EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]]: ...
def email_verification_get_email_verification_url(recipe: EmailPasswordRecipe, get_email_verification_url: Callable[[User, Any], Awaitable[str]]) -> Callable[[EmailVerificationUser, Any], Awaitable[str]]: ...
def validate_and_normalise_email_verification_config(recipe: EmailPasswordRecipe, config: Union[InputEmailVerificationConfig, None], override: InputOverrideConfig) -> ParentRecipeEmailVerificationConfig: ...

class InputOverrideConfig:
    functions: Any
    apis: Any
    email_verification_feature: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ..., email_verification_feature: Union[EmailVerificationOverrideConfig, None] = ...) -> None: ...

class OverrideConfig:
    functions: Any
    apis: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ...) -> None: ...

class EmailPasswordConfig:
    sign_up_feature: Any
    sign_in_feature: Any
    reset_password_using_token_feature: Any
    email_verification_feature: Any
    override: Any
    def __init__(self, sign_up_feature: SignUpFeature, sign_in_feature: SignInFeature, reset_password_using_token_feature: ResetPasswordUsingTokenFeature, email_verification_feature: ParentRecipeEmailVerificationConfig, override: OverrideConfig) -> None: ...

def validate_and_normalise_user_input(recipe: EmailPasswordRecipe, app_info: AppInfo, sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ...) -> EmailPasswordConfig: ...
