from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union


class AddRoleToUserOkResult:
    def __init__(self, did_user_already_have_role: bool):
        self.did_user_already_have_role = did_user_already_have_role


class UnknownRoleError:
    pass


class RemoveUserRoleOkResult:
    def __init__(self, did_user_have_role: bool):
        self.did_user_have_role = did_user_have_role


class GetRolesForUserOkResult:
    def __init__(self, roles: List[str]):
        self.roles = roles


class GetUsersThatHaveRoleOkResult:
    def __init__(self, users: List[str]):
        self.users = users


class CreateNewRoleOrAddPermissionsOkResult:
    def __init__(self, created_new_role: bool):
        self.created_new_role = created_new_role


class GetPermissionsForRoleOkResult:
    def __init__(self, permissions: List[str]):
        self.permissions = permissions


class RemovePermissionsFromRoleOkResult:
    pass


class GetRolesThatHavePermissionOkResult:
    def __init__(self, roles: List[str]):
        self.roles = roles


class DeleteRoleOkResult:
    def __init__(self, did_role_exist: bool):
        self.did_role_exist = did_role_exist


class GetAllRolesOkResult:
    def __init__(self, roles: List[str]):
        self.roles = roles


class RecipeInterface(ABC):
    @abstractmethod
    async def add_role_to_user(
        self,
        user_id: str,
        role: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[AddRoleToUserOkResult, UnknownRoleError]:
        pass

    @abstractmethod
    async def remove_user_role(
        self,
        user_id: str,
        role: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[RemoveUserRoleOkResult, UnknownRoleError]:
        pass

    @abstractmethod
    async def get_roles_for_user(
        self, user_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> GetRolesForUserOkResult:
        pass

    @abstractmethod
    async def get_users_that_have_role(
        self, role: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[GetUsersThatHaveRoleOkResult, UnknownRoleError]:
        pass

    @abstractmethod
    async def create_new_role_or_add_permissions(
        self, role: str, permissions: List[str], user_context: Dict[str, Any]
    ) -> CreateNewRoleOrAddPermissionsOkResult:
        pass

    @abstractmethod
    async def get_permissions_for_role(
        self, role: str, user_context: Dict[str, Any]
    ) -> Union[GetPermissionsForRoleOkResult, UnknownRoleError]:
        pass

    @abstractmethod
    async def remove_permissions_from_role(
        self, role: str, permissions: List[str], user_context: Dict[str, Any]
    ) -> Union[RemovePermissionsFromRoleOkResult, UnknownRoleError]:
        pass

    @abstractmethod
    async def get_roles_that_have_permission(
        self, permission: str, user_context: Dict[str, Any]
    ) -> GetRolesThatHavePermissionOkResult:
        pass

    @abstractmethod
    async def delete_role(
        self, role: str, user_context: Dict[str, Any]
    ) -> DeleteRoleOkResult:
        pass

    @abstractmethod
    async def get_all_roles(self, user_context: Dict[str, Any]) -> GetAllRolesOkResult:
        pass


class APIInterface(ABC):
    pass
