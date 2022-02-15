from .recipe_module import RecipeModule
from .supertokens import AppInfo, InputAppInfo, SupertokensConfig
from typing import Callable, List, Union
from typing_extensions import Literal

def init(app_info: InputAppInfo, framework: Literal['fastapi', 'flask', 'django'], supertokens_config: SupertokensConfig, recipe_list: List[Callable[[AppInfo], RecipeModule]], mode: Union[Literal['asgi', 'wsgi'], None] = ..., telemetry: Union[bool, None] = ...): ...
def get_all_cors_headers(): ...
