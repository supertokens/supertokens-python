from .interfaces import APIInterface as APIInterface, RecipeInterface as RecipeInterface
from typing import Any, Callable, Union

class OverrideConfig:
    functions: Any
    apis: Any
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = ..., apis: Union[Callable[[APIInterface], APIInterface], None] = ...) -> None: ...

class JWTConfig:
    override: Any
    jwt_validity_seconds: Any
    def __init__(self, override: OverrideConfig, jwt_validity_seconds: int) -> None: ...

def validate_and_normalise_user_input(jwt_validity_seconds: Union[int, None] = ..., override: Union[OverrideConfig, None] = ...): ...
