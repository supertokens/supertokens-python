from typing import Optional

from supertokens_python.recipe.webauthn.interfaces.api import ApiInterface, APIOptions
from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.recipe.webauthn.types.config import (
    NormalisedWebauthnConfig,
    WebauthnConfig,
)

# Some Pydantic models need a rebuild to resolve ForwardRefs
# Referencing imports here to prevent lint errors.
# Caveat: These will be available for import from this module directly.
ApiInterface  # type: ignore
RecipeInterface  # type: ignore
NormalisedWebauthnConfig  # type: ignore


# APIOptions - ApiInterface -> WebauthnConfig/NormalisedWebauthnConfig -> RecipeInterface
APIOptions.model_rebuild()


def init(config: Optional[WebauthnConfig] = None):
    return WebauthnRecipe.init(config=config)
