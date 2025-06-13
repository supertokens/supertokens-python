from typing import Any, List, Union

from typing_extensions import Literal

from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.userroles.asyncio import get_all_roles
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.types.response import APIResponse


class OkResponse(APIResponse):
    def __init__(self, roles: List[str]):
        self.status: Literal["OK"] = "OK"
        self.roles = roles

    def to_json(self):
        return {"status": self.status, "roles": self.roles}


class FeatureNotEnabledErrorResponse(APIResponse):
    def __init__(self):
        self.status: Literal["FEATURE_NOT_ENABLED_ERROR"] = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


async def get_all_roles_api(
    _: APIInterface, __: str, ___: APIOptions, ____: Any
) -> Union[OkResponse, FeatureNotEnabledErrorResponse]:
    try:
        UserRolesRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledErrorResponse()

    response = await get_all_roles()
    return OkResponse(roles=response.roles)
