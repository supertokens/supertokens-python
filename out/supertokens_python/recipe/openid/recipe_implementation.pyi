from .interfaces import CreateJwtResult as CreateJwtResult, GetJWKSResult as GetJWKSResult, GetOpenIdDiscoveryConfigurationResult as GetOpenIdDiscoveryConfigurationResult, RecipeInterface as RecipeInterface
from .utils import OpenIdConfig as OpenIdConfig
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.jwt.constants import GET_JWKS_API as GET_JWKS_API
from supertokens_python.recipe.jwt.interfaces import RecipeInterface as JWTRecipeInterface
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Dict, Union

class RecipeImplementation(RecipeInterface):
    async def get_open_id_discovery_configuration(self, user_context: Dict[str, Any]) -> GetOpenIdDiscoveryConfigurationResult: ...
    querier: Any
    config: Any
    app_info: Any
    jwt_recipe_implementation: Any
    def __init__(self, querier: Querier, config: OpenIdConfig, app_info: AppInfo, jwt_recipe_implementation: JWTRecipeInterface) -> None: ...
    async def create_jwt(self, payload: Dict[str, Any], validity_seconds: Union[int, None], user_context: Dict[str, Any]) -> CreateJwtResult: ...
    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult: ...
