from supertokens_python.async_to_sync_wrapper import sync as sync
from supertokens_python.recipe.jwt import asyncio as asyncio
from supertokens_python.recipe.jwt.interfaces import CreateJwtResult as CreateJwtResult, GetJWKSResult as GetJWKSResult
from typing import Any, Dict, Union

def create_jwt(payload: Union[None, Dict[str, Any]] = ..., validity_seconds: Union[None, int] = ..., user_context: Union[Dict[str, Any], None] = ...) -> CreateJwtResult: ...
def get_jwks(user_context: Union[Dict[str, Any], None] = ...) -> GetJWKSResult: ...
