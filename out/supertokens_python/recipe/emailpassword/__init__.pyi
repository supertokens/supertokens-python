from . import exceptions as exceptions
from ...recipe_module import RecipeModule
from .recipe import EmailPasswordRecipe as EmailPasswordRecipe
from .utils import InputEmailVerificationConfig as InputEmailVerificationConfig, InputFormField as InputFormField, InputOverrideConfig as InputOverrideConfig, InputResetPasswordUsingTokenFeature as InputResetPasswordUsingTokenFeature, InputSignUpFeature as InputSignUpFeature
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Callable, Union

def init(sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ...) -> Callable[[AppInfo], RecipeModule]: ...
