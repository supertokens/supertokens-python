from . import exceptions as exceptions
from ...recipe_module import RecipeModule
from .recipe import EmailVerificationRecipe as EmailVerificationRecipe
from .utils import ParentRecipeEmailVerificationConfig as ParentRecipeEmailVerificationConfig
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Callable

def init(config: ParentRecipeEmailVerificationConfig) -> Callable[[AppInfo], RecipeModule]: ...
