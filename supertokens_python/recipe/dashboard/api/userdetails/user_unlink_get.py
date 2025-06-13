from typing import Any, Dict

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.accountlinking.asyncio import unlink_account
from supertokens_python.recipe.dashboard.utils import RecipeUserId
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions


class UserUnlinkGetOkResult(APIResponse):
    def __init__(self):
        self.status: Literal["OK"] = "OK"

    def to_json(self):
        return {"status": self.status}


async def handle_user_unlink_get(
    _api_interface: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> UserUnlinkGetOkResult:
    recipe_user_id = api_options.request.get_query_param("recipeUserId")

    if recipe_user_id is None:
        raise_bad_input_exception("Required field recipeUserId is missing")

    await unlink_account(RecipeUserId(recipe_user_id), user_context)

    return UserUnlinkGetOkResult()
