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

from typing import Union, Dict, Any, Optional

from supertokens_python.recipe.useridmapping.interfaces import (
    UserIdMappingAlreadyExistsError,
    UnknownMappingError,
    UpdateOrDeleteUserIdMappingInfoOkResult,
    UserIDTypes,
    CreateUserIdMappingOkResult,
    UnknownSupertokensUserIDError,
    GetUserIdMappingOkResult,
    DeleteUserIdMappingOkResult,
)

from supertokens_python.recipe.useridmapping.recipe import UserIdMappingRecipe


async def create_user_id_mapping(
    supertokens_user_id: str,
    external_user_id: str,
    external_user_id_info: Optional[str],
    user_context: Dict[str, Any],
) -> Union[
    CreateUserIdMappingOkResult,
    UnknownSupertokensUserIDError,
    UserIdMappingAlreadyExistsError,
]:
    return await UserIdMappingRecipe.get_instance().recipe_implementation.create_user_id_mapping(
        supertokens_user_id, external_user_id, external_user_id_info, user_context
    )


async def get_user_id_mapping(
    user_id: str, user_id_type: UserIDTypes, user_context: Dict[str, Any]
) -> Union[GetUserIdMappingOkResult, UnknownMappingError]:
    return await UserIdMappingRecipe.get_instance().recipe_implementation.get_user_id_mapping(
        user_id, user_id_type, user_context
    )


async def delete_user_id_mapping(
    user_id: str, user_id_type: UserIDTypes, user_context: Dict[str, Any]
) -> Union[DeleteUserIdMappingOkResult, UnknownMappingError]:
    return await UserIdMappingRecipe.get_instance().recipe_implementation.delete_user_id_mapping(
        user_id, user_id_type, user_context
    )


async def update_or_delete_user_id_mapping_info(
    user_id: str,
    user_id_type: UserIDTypes,
    external_user_id_info: Optional[str],
    user_context: Dict[str, Any],
) -> Union[UpdateOrDeleteUserIdMappingInfoOkResult, UnknownMappingError]:
    return await UserIdMappingRecipe.get_instance().recipe_implementation.update_or_delete_user_id_mapping_info(
        user_id, user_id_type, external_user_id_info, user_context
    )
