from typing import Any, Union

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.userroles.asyncio import add_role_to_user
from supertokens_python.recipe.userroles.interfaces import AddRoleToUserOkResult
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.types.response import APIResponse


class OkResponse(APIResponse):
    def __init__(self, did_user_already_have_role: bool):
        self.status: Literal["OK"] = "OK"
        self.did_user_already_have_role = did_user_already_have_role

    def to_json(self):
        return {
            "status": self.status,
            "didUserAlreadyHaveRole": self.did_user_already_have_role,
        }


class FeatureNotEnabledErrorResponse(APIResponse):
    def __init__(self):
        self.status: Literal["FEATURE_NOT_ENABLED_ERROR"] = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


class UnknownRoleErrorResponse(APIResponse):
    def __init__(self):
        self.status: Literal["UNKNOWN_ROLE_ERROR"] = "UNKNOWN_ROLE_ERROR"

    def to_json(self):
        return {"status": self.status}


async def add_role_to_user_api(
    _: APIInterface, tenant_id: str, api_options: APIOptions, __: Any
) -> Union[OkResponse, FeatureNotEnabledErrorResponse, UnknownRoleErrorResponse]:
    try:
        UserRolesRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledErrorResponse()

    request_body = await api_options.request.json()
    if request_body is None:
        raise_bad_input_exception("Request body is missing")

    user_id = request_body.get("userId")
    role = request_body.get("role")

    if role is None or not isinstance(role, str):
        raise_bad_input_exception(
            "Required parameter 'role' is missing or has an invalid type"
        )

    if user_id is None or not isinstance(user_id, str):
        raise_bad_input_exception(
            "Required parameter 'userId' is missing or has an invalid type"
        )

    response = await add_role_to_user(tenant_id, user_id, role)

    if isinstance(response, AddRoleToUserOkResult):
        return OkResponse(
            did_user_already_have_role=response.did_user_already_have_role
        )
    else:
        return UnknownRoleErrorResponse()
