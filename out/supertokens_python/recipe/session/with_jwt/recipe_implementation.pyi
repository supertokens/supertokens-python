from .constants import ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY as ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY
from .session_class import get_session_with_jwt as get_session_with_jwt
from .utills import add_jwt_to_access_token_payload as add_jwt_to_access_token_payload
from supertokens_python.recipe.openid.interfaces import RecipeInterface as OpenIdRecipeInterface
from supertokens_python.recipe.session.interfaces import RecipeInterface as RecipeInterface, SessionContainer as SessionContainer
from supertokens_python.recipe.session.utils import SessionConfig as SessionConfig
from supertokens_python.utils import get_timestamp_ms as get_timestamp_ms

EXPIRY_OFFSET_SECONDS: int

def get_jwt_expiry(access_token_expiry: int): ...
def get_recipe_implementation_with_jwt(original_implementation: RecipeInterface, config: SessionConfig, openid_recipe_implementation: OpenIdRecipeInterface) -> RecipeInterface: ...
