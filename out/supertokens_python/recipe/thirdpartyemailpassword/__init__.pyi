from . import exceptions as exceptions
from ...recipe_module import RecipeModule
from ..emailpassword import InputResetPasswordUsingTokenFeature as InputResetPasswordUsingTokenFeature, InputSignUpFeature as InputSignUpFeature
from .recipe import ThirdPartyEmailPasswordRecipe as ThirdPartyEmailPasswordRecipe
from .utils import InputEmailVerificationConfig as InputEmailVerificationConfig, InputOverrideConfig as InputOverrideConfig
from supertokens_python.recipe.thirdparty import Apple as Apple, Discord as Discord, Facebook as Facebook, Github as Github, Google as Google, GoogleWorkspaces as GoogleWorkspaces
from supertokens_python.recipe.thirdparty.provider import Provider as Provider
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Callable, List, Union

def init(sign_up_feature: Union[InputSignUpFeature, None] = ..., reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = ..., email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ..., providers: Union[List[Provider], None] = ...) -> Callable[[AppInfo], RecipeModule]: ...
