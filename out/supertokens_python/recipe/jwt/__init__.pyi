from ...recipe_module import RecipeModule
from .recipe import JWTRecipe as JWTRecipe
from .utils import OverrideConfig as OverrideConfig
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Callable, Union

def init(jwt_validity_seconds: Union[int, None] = ..., override: Union[OverrideConfig, None] = ...) -> Callable[[AppInfo], RecipeModule]: ...
