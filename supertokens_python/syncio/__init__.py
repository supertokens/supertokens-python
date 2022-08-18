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
from typing import List, Union, Optional

from supertokens_python import Supertokens
from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.interfaces import (
    CreateUserIdMappingOkResult,
    UnknownSupertokensUserIDError,
    UserIdMappingAlreadyExistsError,
    UserIDTypes,
    UnknownMappingError,
    GetUserIdMappingOkResult,
    DeleteUserIdMappingOkResult,
    UpdateOrDeleteUserIdMappingInfoOkResult,
)
from supertokens_python.types import UsersResponse


def get_users_oldest_first(
    limit: Union[int, None] = None,
    pagination_token: Union[str, None] = None,
    include_recipe_ids: Union[None, List[str]] = None,
) -> UsersResponse:
    return sync(
        Supertokens.get_instance().get_users(
            "ASC", limit, pagination_token, include_recipe_ids
        )
    )


def get_users_newest_first(
    limit: Union[int, None] = None,
    pagination_token: Union[str, None] = None,
    include_recipe_ids: Union[None, List[str]] = None,
) -> UsersResponse:
    return sync(
        Supertokens.get_instance().get_users(
            "DESC", limit, pagination_token, include_recipe_ids
        )
    )


def get_user_count(include_recipe_ids: Union[None, List[str]] = None) -> int:
    return sync(Supertokens.get_instance().get_user_count(include_recipe_ids))


def delete_user(user_id: str) -> None:
    return sync(Supertokens.get_instance().delete_user(user_id))


def create_user_id_mapping(
    supertokens_user_id: str,
    external_user_id: str,
    external_user_id_info: Optional[str] = None,
) -> Union[
    CreateUserIdMappingOkResult,
    UnknownSupertokensUserIDError,
    UserIdMappingAlreadyExistsError,
]:
    return sync(
        Supertokens.get_instance().create_user_id_mapping(
            supertokens_user_id, external_user_id, external_user_id_info
        )
    )


def get_user_id_mapping(
    user_id: str,
    user_id_type: Optional[UserIDTypes] = None,
) -> Union[GetUserIdMappingOkResult, UnknownMappingError]:
    return sync(Supertokens.get_instance().get_user_id_mapping(user_id, user_id_type))


def delete_user_id_mapping(
    user_id: str, user_id_type: Optional[UserIDTypes] = None
) -> DeleteUserIdMappingOkResult:
    return sync(
        Supertokens.get_instance().delete_user_id_mapping(user_id, user_id_type)
    )


def update_or_delete_user_id_mapping_info(
    user_id: str,
    user_id_type: Optional[UserIDTypes] = None,
    external_user_id_info: Optional[str] = None,
) -> Union[UpdateOrDeleteUserIdMappingInfoOkResult, UnknownMappingError]:
    return sync(
        Supertokens.get_instance().update_or_delete_user_id_mapping_info(
            user_id, user_id_type, external_user_id_info
        )
    )
