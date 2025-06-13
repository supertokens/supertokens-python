from typing import Any, Union

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.userroles.asyncio import delete_role
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.types.response import APIResponse


class OkResponse(APIResponse):
    def __init__(self, did_role_exist: bool):
        self.status: Literal["OK"] = "OK"
        self.did_role_exist = did_role_exist

    def to_json(self):
        return {"status": self.status, "didRoleExist": self.did_role_exist}


class FeatureNotEnabledErrorResponse(APIResponse):
    def __init__(self):
        self.status: Literal["FEATURE_NOT_ENABLED_ERROR"] = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


async def delete_role_api(
    _: APIInterface, __: str, api_options: APIOptions, ___: Any
) -> Union[OkResponse, FeatureNotEnabledErrorResponse]:
    try:
        UserRolesRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledErrorResponse()

    role = api_options.request.get_query_param("role")

    if role is None:
        raise_bad_input_exception(
            "Required parameter 'role' is missing or has an invalid type"
        )

    response = await delete_role(role)
    return OkResponse(did_role_exist=response.did_role_exist)
