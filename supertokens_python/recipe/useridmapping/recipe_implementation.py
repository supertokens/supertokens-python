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


from typing import Any, Dict, Union, Optional

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from .interfaces import (
    RecipeInterface,
    UnknownMappingError,
    UnknownSupertokensUserIDError,
    DeleteUserIdMappingOkResult,
    UserIDTypes,
    UpdateOrDeleteUserIdMappingInfoOkResult,
    GetUserIdMappingOkResult,
    UserIdMappingAlreadyExistsError,
    CreateUserIdMappingOkResult,
)


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

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
        return await self.querier.send_post_request(
            NormalisedURLPath("/recipe/userid/map"),
            {
                "supertokensUserId": supertokens_user_id,
                "externalUserId": external_user_id,
                "externalUserIdInfo": external_user_id_info,
            },
        )

    async def get_user_id_mapping(
        self, user_id: str, user_id_type: UserIDTypes, user_context: Dict[str, Any]
    ) -> Union[GetUserIdMappingOkResult, UnknownMappingError]:
        if user_context.get("_default", {}).get("userIdMapping") is not None:
            return user_context["_default"]["userIdMapping"]

        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/userid/map"),
            {"userId": user_id, "userIdType": user_id_type},
        )

        user_context["_default"] = {
            **user_context["_default"],
            "userIdMapping": response,
        }

        return response

    async def delete_user_id_mapping(
        self, user_id: str, user_id_type: UserIDTypes, user_context: Dict[str, Any]
    ) -> DeleteUserIdMappingOkResult:
        return await self.querier.send_post_request(
            NormalisedURLPath("/recipe/userid/map/remove"),
            {"userId": user_id, "userIdType": user_id_type},
        )

    async def update_or_delete_user_id_mapping_info(
        self,
        user_id: str,
        user_id_type: UserIDTypes,
        external_user_id_info: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[UpdateOrDeleteUserIdMappingInfoOkResult, UnknownMappingError]:
        return await self.querier.send_put_request(
            NormalisedURLPath("/recipe/userid/map/info"),
            {
                "userId": user_id,
                "userIdType": user_id_type,
                "externalUserIdInfo": external_user_id_info,
            },
        )
