from typing import Optional

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
        external_user_info: Optional[str] = None,  # TODO: Shouldn't this be a dict?
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
