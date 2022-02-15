from . import exceptions as exceptions
from ...recipe_module import RecipeModule
from .providers import Apple as Apple, Discord as Discord, Facebook as Facebook, Github as Github, Google as Google, GoogleWorkspaces as GoogleWorkspaces
from .recipe import ThirdPartyRecipe as ThirdPartyRecipe
from .utils import InputEmailVerificationConfig as InputEmailVerificationConfig, InputOverrideConfig as InputOverrideConfig, SignInAndUpFeature as SignInAndUpFeature
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Callable, Union

def init(sign_in_and_up_feature: SignInAndUpFeature, email_verification_feature: Union[InputEmailVerificationConfig, None] = ..., override: Union[InputOverrideConfig, None] = ...) -> Callable[[AppInfo], RecipeModule]: ...
