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


from typing import Any, Dict

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

from .interfaces import ClearUserMetadataResult, MetadataResult, RecipeInterface


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def get_user_metadata(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> MetadataResult:
        params = {"userId": user_id}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user/metadata"), params
        )
        return MetadataResult(metadata=response["metadata"])

    async def update_user_metadata(
        self,
        user_id: str,
        metadata_update: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> MetadataResult:
        params = {"userId": user_id, "metadataUpdate": metadata_update}
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user/metadata"), params
        )
        return MetadataResult(metadata=response["metadata"])

    async def clear_user_metadata(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> ClearUserMetadataResult:
        params = {"userId": user_id}
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/user/metadata/remove"), params
        )
        return ClearUserMetadataResult()
