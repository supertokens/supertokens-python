from typing import Any, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.userroles.asyncio import (
    create_new_role_or_add_permissions,
)
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.types.response import APIResponse


class OkResponse(APIResponse):
    def __init__(self, created_new_role: bool):
        self.status = "OK"
        self.created_new_role = created_new_role

    def to_json(self):
        return {"status": self.status, "createdNewRole": self.created_new_role}


class FeatureNotEnabledErrorResponse(APIResponse):
    def __init__(self):
        self.status = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


async def create_role_or_add_permissions_api(
    _: APIInterface, __: str, api_options: APIOptions, ___: Any
) -> Union[OkResponse, FeatureNotEnabledErrorResponse]:
    try:
        UserRolesRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledErrorResponse()

    request_body = await api_options.request.json()
    if request_body is None:
        raise_bad_input_exception("Request body is missing")

    role = request_body.get("role")
    permissions: Union[List[str], None] = request_body.get("permissions")

    if role is None or not isinstance(role, str):
        raise_bad_input_exception(
            "Required parameter 'role' is missing or has an invalid type"
        )

    if permissions is None:
        raise_bad_input_exception(
            "Required parameter 'permissions' is missing or has an invalid type"
        )

    response = await create_new_role_or_add_permissions(role, permissions)
    return OkResponse(created_new_role=response.created_new_role)
