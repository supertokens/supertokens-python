from typing import Optional

from supertokens_python.recipe.webauthn.functions import (
    consume_recover_account_token,
    create_new_recipe_user,
    generate_recover_account_token,
    get_credential,
    get_generated_options,
    get_user_from_recover_account_token,
    list_credentials,
    register_credential,
    register_options,
    remove_credential,
    remove_generated_options,
    sign_in,
    sign_in_options,
    sign_up,
    update_user_email,
    verify_credentials,
)
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


__all__ = [
    "init",
    "register_options",
    "sign_in_options",
    "sign_up",
    "sign_in",
    "verify_credentials",
    "create_new_recipe_user",
    "generate_recover_account_token",
    "consume_recover_account_token",
    "register_credential",
    "get_user_from_recover_account_token",
    "remove_credential",
    "get_credential",
    "list_credentials",
    "remove_generated_options",
    "get_generated_options",
    "update_user_email",
    "WebauthnConfig",
    "WebauthnRecipe",
]
