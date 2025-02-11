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
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Awaitable, Dict, List

from ...usermetadata import UserMetadataRecipe
from ...usermetadata.asyncio import get_user_metadata
from ..interfaces import DashboardUsersGetResponse
from ..utils import UserWithMetadata

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIInterface,
        APIOptions,
    )

from supertokens_python.asyncio import get_users_newest_first, get_users_oldest_first
from supertokens_python.exceptions import GeneralError, raise_bad_input_exception


async def handle_users_get_api(
    api_implementation: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> DashboardUsersGetResponse:
    _ = api_implementation

    limit = api_options.request.get_query_param("limit")
    if limit is None:
        raise_bad_input_exception("Missing required parameter 'limit'")

    time_joined_order = api_options.request.get_query_param("timeJoinedOrder", "DESC")
    if time_joined_order not in ["ASC", "DESC"]:
        raise_bad_input_exception("Invalid value received for 'timeJoinedOrder'")

    pagination_token = api_options.request.get_query_param("paginationToken")
    query = get_search_params_from_url(api_options.request.get_original_url())

    users_response = await (
        get_users_newest_first
        if time_joined_order == "DESC"
        else get_users_oldest_first
    )(
        tenant_id,
        limit=int(limit),
        pagination_token=pagination_token,
        query=query,
        user_context=user_context,
    )

    try:
        UserMetadataRecipe.get_instance()
    except GeneralError:
        users_with_metadata: List[UserWithMetadata] = [
            UserWithMetadata().from_user(user) for user in users_response.users
        ]
        return DashboardUsersGetResponse(
            users_with_metadata, users_response.next_pagination_token
        )

    users_with_metadata: List[UserWithMetadata] = [
        UserWithMetadata().from_user(user) for user in users_response.users
    ]
    metadata_fetch_awaitables: List[Awaitable[Any]] = []

    async def get_user_metadata_and_update_user(user_idx: int) -> None:
        user = users_response.users[user_idx]
        user_metadata = await get_user_metadata(user.id)
        first_name = user_metadata.metadata.get("first_name")
        last_name = user_metadata.metadata.get("last_name")

        users_with_metadata[user_idx].first_name = first_name
        users_with_metadata[user_idx].last_name = last_name

    for i, _ in enumerate(users_response.users):
        metadata_fetch_awaitables.append(get_user_metadata_and_update_user(i))

    promise_arr_start_position = 0
    batch_size = 5

    while promise_arr_start_position < len(metadata_fetch_awaitables):
        # We want to query only 5 in parallel at a time
        promises_to_call = [
            metadata_fetch_awaitables[i]
            for i in range(
                promise_arr_start_position,
                min(
                    promise_arr_start_position + batch_size,
                    len(metadata_fetch_awaitables),
                ),
            )
        ]
        await asyncio.gather(*promises_to_call)
        promise_arr_start_position += batch_size

    return DashboardUsersGetResponse(
        users_with_metadata,
        users_response.next_pagination_token,
    )


def get_search_params_from_url(path: str) -> Dict[str, str]:
    from urllib.parse import parse_qs, urlparse

    url_object = urlparse("https://example.com" + path)
    params = parse_qs(url_object.query)
    search_query = {
        key: value[0]
        for key, value in params.items()
        if key not in ["limit", "timeJoinedOrder", "paginationToken"]
    }
    return search_query
