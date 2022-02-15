from .constants import ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY as ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY
from supertokens_python.recipe.openid.interfaces import RecipeInterface as RecipeInterface
from typing import Any, Dict

async def add_jwt_to_access_token_payload(access_token_payload: Dict[str, Any], jwt_expiry: int, user_id: str, jwt_property_name: str, openid_recipe_implementation: RecipeInterface, user_context: Dict[str, Any]): ...
