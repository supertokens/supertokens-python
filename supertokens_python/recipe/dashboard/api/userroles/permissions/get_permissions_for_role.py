from typing import Any, Dict, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.userroles.asyncio import get_permissions_for_role
from supertokens_python.recipe.userroles.interfaces import (
    GetPermissionsForRoleOkResult,
)
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.types.response import APIResponse


class OkPermissionsForRoleResponse(APIResponse):
    def __init__(self, permissions: List[str]):
        self.status = "OK"
        self.permissions = permissions

    def to_json(self):
        return {"status": self.status, "permissions": self.permissions}


class FeatureNotEnabledErrorResponse(APIResponse):
    def __init__(self):
        self.status = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


class UnknownRoleErrorResponse(APIResponse):
    def __init__(self):
        self.status = "UNKNOWN_ROLE_ERROR"

    def to_json(self):
        return {"status": self.status}


async def get_permissions_for_role_api(
    _: APIInterface,
    __: str,
    api_options: APIOptions,
    ___: Dict[str, Any],
) -> Union[
    OkPermissionsForRoleResponse,
    FeatureNotEnabledErrorResponse,
    UnknownRoleErrorResponse,
]:
    try:
        UserRolesRecipe.get_instance()
    except Exception:
        return FeatureNotEnabledErrorResponse()

    role = api_options.request.get_query_param("role")

    if role is None:
        raise_bad_input_exception("Required parameter 'role' is missing")

    response = await get_permissions_for_role(role)

    if isinstance(response, GetPermissionsForRoleOkResult):
        return OkPermissionsForRoleResponse(response.permissions)
    else:
        return UnknownRoleErrorResponse()
