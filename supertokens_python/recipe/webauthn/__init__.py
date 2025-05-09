from typing import Optional

from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.recipe.webauthn.types.config import WebauthnConfig


def init(config: Optional[WebauthnConfig] = None):
    return WebauthnRecipe.init(config=config)
