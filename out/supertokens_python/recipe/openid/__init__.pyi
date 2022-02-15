from ...recipe_module import RecipeModule
from .recipe import OpenIdRecipe as OpenIdRecipe
from .utils import InputOverrideConfig as InputOverrideConfig
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Callable, Union

def init(jwt_validity_seconds: Union[int, None] = ..., issuer: Union[str, None] = ..., override: Union[InputOverrideConfig, None] = ...) -> Callable[[AppInfo], RecipeModule]: ...
