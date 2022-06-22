from typing import Any, Dict, Union, List

from supertokens_python.recipe.userroles.interfaces import (AddRoleToUserResult,
                                                            DeleteRoleResult,
                                                            GetRolesForUserResult,
                                                            RemovePermissionsFromRoleResult,
                                                            RemoveUserRoleResult, GetUsersThatHaveRoleResult,
                                                            CreateNewRoleOrAddPermissionsResult,
                                                            GetPermissionsForRoleResult,
                                                            GetRolesThatHavePermissionResult, GetAllRolesResult, )

from supertokens_python.recipe.userroles.recipe import UserRolesRecipe


async def add_role_to_user(user_id: str, role: str,
                           user_context: Union[Dict[str, Any], None] = None) -> AddRoleToUserResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.add_role_to_user(user_id, role, user_context)


async def remove_user_role(user_id: str, role: str, user_context: Dict[str, Any]) -> RemoveUserRoleResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.remove_user_role(user_id, role, user_context)


async def get_roles_for_user(user_id: str, user_context: Dict[str, Any]) -> GetRolesForUserResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.get_roles_for_user(user_id, user_context)


async def get_users_that_have_role(role: str, user_context: Dict[str, Any]) -> GetUsersThatHaveRoleResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.get_users_that_have_role(role, user_context)


async def create_new_role_or_add_permissions(role: str, permissions: List[str],
                                             user_context: Dict[str, Any]) -> CreateNewRoleOrAddPermissionsResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.create_new_role_or_add_permissions(role,
                                                                                                         permissions,
                                                                                                         user_context)


async def get_permissions_for_role(role: str, user_context: Dict[str, Any]) -> GetPermissionsForRoleResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.get_permissions_for_role(role, user_context)


async def remove_permissions_from_role(role: str, permissions: List[str],
                                       user_context: Dict[str, Any]) -> RemovePermissionsFromRoleResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.remove_permissions_from_role(role, permissions,
                                                                                                   user_context)


async def get_roles_that_have_permission(permission: str,
                                         user_context: Dict[str, Any]) -> GetRolesThatHavePermissionResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.get_roles_that_have_permission(permission,
                                                                                                     user_context)


async def delete_role(role: str, user_context: Dict[str, Any]) -> DeleteRoleResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.delete_role(role, user_context)


async def get_all_roles(user_context: Dict[str, Any]) -> GetAllRolesResult:
    if user_context is None:
        user_context = {}
    return await UserRolesRecipe.get_instance().recipe_implementation.get_all_roles(user_context)
