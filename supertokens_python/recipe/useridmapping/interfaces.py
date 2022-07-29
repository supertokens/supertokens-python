from abc import ABC, abstractmethod
from typing import Any, Dict, Union, Optional
from typing_extensions import Literal


class UnknownSupertokensUserIDError:
    pass


class CreateUserIdMappingOkResult:
    pass


class UserIdMappingAlreadyExistsError:
    def __init__(
        self, does_super_tokens_user_id_exist: bool, does_external_user_id_exist: str
    ):
        self.does_super_tokens_user_id_exist = does_super_tokens_user_id_exist
        self.does_external_user_id_exist = does_external_user_id_exist


UserIDTypes = Literal["SUPERTOKENS", "EXTERNAL", "ANY"]


class GetUserIdMappingOkResult:
    def __init__(
        self,
        supertokens_user_id: str,
        external_user_id: str,
        external_user_info: Optional[str],
    ):
        self.supertokens_user_id = supertokens_user_id
        self.external_user_id = external_user_id
        self.external_user_info = external_user_info


class UnknownMappingError:
    pass


class DeleteUserIdMappingOkResult:
    def __init__(self, did_mapping_exist: bool):
        self.did_mapping_exist = did_mapping_exist


class UpdateOrDeleteUserIdMappingInfoOkResult:
    pass


class RecipeInterface(ABC):
    @abstractmethod
    async def create_user_id_mapping(
        self,
        supertokens_user_id: str,
        external_user_id: str,
        external_user_id_info: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateUserIdMappingOkResult,
        UnknownSupertokensUserIDError,
        UserIdMappingAlreadyExistsError,
    ]:
        pass

    @abstractmethod
    async def get_user_id_mapping(
        self, user_id: str, user_id_type: UserIDTypes, user_context: Dict[str, Any]
    ) -> Union[GetUserIdMappingOkResult, UnknownMappingError]:
        pass

    @abstractmethod
    async def delete_user_id_mapping(
        self, user_id: str, user_id_type: UserIDTypes, user_context: Dict[str, Any]
    ) -> DeleteUserIdMappingOkResult:
        pass

    @abstractmethod
    async def update_or_delete_user_id_mapping_info(
        self,
        user_id: str,
        user_id_type: UserIDTypes,
        external_user_id_info: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[UpdateOrDeleteUserIdMappingInfoOkResult, UnknownMappingError]:
        pass


class APIInterface(ABC):
    pass
