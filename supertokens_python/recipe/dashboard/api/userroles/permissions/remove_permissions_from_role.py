from typing import Any, Dict, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.userroles.asyncio import remove_permissions_from_role
from supertokens_python.recipe.userroles.interfaces import (
    RemovePermissionsFromRoleOkResult,
)
from supertokens_python.recipe.userroles.recipe import UserRolesRecipe
from supertokens_python.types.response import APIResponse


class OkResponse(APIResponse):
    def __init__(self):
        self.status = "OK"

    def to_json(self):
        return {"status": self.status}


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


async def remove_permissions_from_role_api(
    _: APIInterface, __: str, api_options: APIOptions, ___: Dict[str, Any]
) -> Union[OkResponse, FeatureNotEnabledErrorResponse, UnknownRoleErrorResponse]:
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

    response = await remove_permissions_from_role(role, permissions)
    if isinstance(response, RemovePermissionsFromRoleOkResult):
        return OkResponse()
    else:
        return UnknownRoleErrorResponse()
