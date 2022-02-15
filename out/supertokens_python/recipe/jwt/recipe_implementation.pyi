from .interfaces import CreateJwtResult as CreateJwtResult, JsonWebKey as JsonWebKey
from .utils import JWTConfig as JWTConfig
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.querier import Querier as Querier
from supertokens_python.recipe.jwt.interfaces import CreateJwtResultOk as CreateJwtResultOk, CreateJwtResultUnsupportedAlgorithm as CreateJwtResultUnsupportedAlgorithm, GetJWKSResult as GetJWKSResult, RecipeInterface as RecipeInterface
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Dict, Union

class RecipeImplementation(RecipeInterface):
    querier: Any
    config: Any
    app_info: Any
    def __init__(self, querier: Querier, config: JWTConfig, app_info: AppInfo) -> None: ...
    async def create_jwt(self, payload: Dict[str, Any], validity_seconds: Union[int, None], user_context: Dict[str, Any]) -> CreateJwtResult: ...
    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult: ...
