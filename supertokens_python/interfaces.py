# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

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
        external_user_info: Optional[str] = None,
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
