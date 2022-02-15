from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from supertokens_python import AppInfo as AppInfo
from supertokens_python.normalised_url_domain import NormalisedURLDomain as NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.recipe.jwt import OverrideConfig as JWTOverrideConfig
from typing import Any, Callable, Union

class InputOverrideConfig:
    functions: Any
    apis: Any
    jwt_feature: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ..., jwt_feature: Union[JWTOverrideConfig, None] = ...) -> None: ...

class OverrideConfig:
    functions: Any
    apis: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ...) -> None: ...

class OpenIdConfig:
    override: Any
    issuer_domain: Any
    issuer_path: Any
    def __init__(self, override: OverrideConfig, issuer_domain: NormalisedURLDomain, issuer_path: NormalisedURLPath) -> None: ...

def validate_and_normalise_user_input(app_info: AppInfo, issuer: Union[str, None] = ..., override: Union[InputOverrideConfig, None] = ...): ...
