from supertokens_python.recipe.jwt.interfaces import APIInterface as APIInterface, APIOptions as APIOptions, JWKSGetResponse as JWKSGetResponse
from typing import Any, Dict

class APIImplementation(APIInterface):
    async def jwks_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> JWKSGetResponse: ...
