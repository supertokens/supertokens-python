from typing import Any, List, Union

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.userroles.asyncio import get_roles_for_user
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.types.response import APIResponse


class OkResponse(APIResponse):
    def __init__(self, roles: List[str]):
        self.status: Literal["OK"] = "OK"
        self.roles = roles

    def to_json(self):
        return {
            "status": self.status,
            "roles": self.roles,
        }


class FeatureNotEnabledErrorResponse(APIResponse):
    def __init__(self):
        self.status: Literal["FEATURE_NOT_ENABLED_ERROR"] = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


async def get_roles_for_user_api(
    _: APIInterface, tenant_id: str, api_options: APIOptions, __: Any
) -> Union[OkResponse, FeatureNotEnabledErrorResponse]:
    try:
        UserRolesRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledErrorResponse()

    user_id = api_options.request.get_query_param("userId")

    if user_id is None:
        raise_bad_input_exception(
            "Required parameter 'userId' is missing or has an invalid type"
        )

    response = await get_roles_for_user(tenant_id, user_id)
    return OkResponse(roles=response.roles)
