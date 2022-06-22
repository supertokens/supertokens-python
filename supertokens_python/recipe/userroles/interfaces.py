from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union


class AddRoleToUserOkResult:
    def __init__(self, did_user_already_have_role: bool):
        self.did_user_already_have_role = did_user_already_have_role


class UnknownRoleError:
    # self.status = "UNKNOWN_ROLE_ERROR"
    pass


AddRoleToUserResult = Union[AddRoleToUserOkResult, UnknownRoleError]


class RemoveUserRoleOkResult:
    def __init__(self, did_user_have_role: bool):
        self.did_user_have_role = did_user_have_role


RemoveUserRoleResult = Union[RemoveUserRoleOkResult, UnknownRoleError]


class GetRolesForUserResult:
    def __init__(self, roles: List[str]):
        self.roles = roles


class GetUsersThatHaveRoleOkResult:
    def __init__(self, users: List[str]):
        self.users = users


GetUsersThatHaveRoleResult = Union[GetUsersThatHaveRoleOkResult, UnknownRoleError]


class CreateNewRoleOrAddPermissionsResult:
    def __init__(self, created_new_role: bool):
        self.created_new_role = created_new_role


class GetPermissionsForRoleOkResult:
    def __init__(self, permissions: List[str]):
        self.permissions = permissions


GetPermissionsForRoleResult = Union[GetPermissionsForRoleOkResult, UnknownRoleError]


class RemovePermissionsFromRoleOkResult:
    pass


RemovePermissionsFromRoleResult = Union[RemovePermissionsFromRoleOkResult, UnknownRoleError]


class GetRolesThatHavePermissionResult:
    def __init__(self, roles: List[str]):
        self.roles = roles


class DeleteRoleResult:
    def __init__(self, did_role_exist: bool):
        self.did_role_exist = did_role_exist


class GetAllRolesResult:
    def __init__(self, roles: List[str]):
        self.roles = roles


class RecipeInterface(ABC):
    @abstractmethod
    async def add_role_to_user(self, user_id: str, role: str, user_context: Dict[str, Any]) -> AddRoleToUserResult:
        pass

    @abstractmethod
    async def remove_user_role(self, user_id: str, role: str, user_context: Dict[str, Any]) -> RemoveUserRoleResult:
        pass

    @abstractmethod
    async def get_roles_for_user(self, user_id: str, user_context: Dict[str, Any]) -> GetRolesForUserResult:
        pass

    @abstractmethod
    async def get_users_that_have_role(self, role: str, user_context: Dict[str, Any]) -> GetUsersThatHaveRoleResult:
        pass

    @abstractmethod
    async def create_new_role_or_add_permissions(self, role: str, permissions: List[str],
                                                 user_context: Dict[str, Any]) -> CreateNewRoleOrAddPermissionsResult:
        pass

    @abstractmethod
    async def get_permissions_for_role(self, role: str, user_context: Dict[str, Any]) -> GetPermissionsForRoleResult:
        pass

    @abstractmethod
    async def remove_permissions_from_role(self, role: str, permissions: List[str],
                                           user_context: Dict[str, Any]) -> RemovePermissionsFromRoleResult:
        pass

    @abstractmethod
    async def get_roles_that_have_permission(self, permission: str,
                                             user_context: Dict[str, Any]) -> GetRolesThatHavePermissionResult:
        pass

    @abstractmethod
    async def delete_role(self, role: str, user_context: Dict[str, Any]) -> DeleteRoleResult:
        pass

    @abstractmethod
    async def get_all_roles(self, user_context: Dict[str, Any]) -> GetAllRolesResult:
        pass


class APIInterface(ABC):
    pass
