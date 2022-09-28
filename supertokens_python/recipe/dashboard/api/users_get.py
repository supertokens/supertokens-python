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
from typing import TYPE_CHECKING, Any, Awaitable, Dict, List, Optional

from supertokens_python.framework import BaseResponse
from supertokens_python.supertokens import Supertokens

from ...usermetadata import UserMetadataRecipe
from ...usermetadata.asyncio import get_user_metadata
from ..interfaces import DashboardUsersGetResponse

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )

from supertokens_python.exceptions import GeneralError, raise_bad_input_exception
from supertokens_python.utils import send_200_response


async def handle_users_get_api(
    api_implementation: APIInterface, api_options: APIOptions
) -> Optional[BaseResponse]:
    _ = api_implementation

    limit = api_options.request.get_query_param("limit")
    if limit is None:
        raise_bad_input_exception("Missing required parameter 'limit'")

    time_joined_order: str = api_options.request.get_query_param(  # type: ignore
        "timeJoinedOrder", "DESC"
    )
    if time_joined_order not in ["ASC", "DESC"]:
        raise_bad_input_exception("Invalid value recieved for 'timeJoinedOrder'")

    pagination_token = api_options.request.get_query_param("paginationToken")

    users_response = await Supertokens.get_instance().get_users(
        limit=int(limit),
        time_joined_order=time_joined_order,  # type: ignore
        pagination_token=pagination_token,
        include_recipe_ids=None,
    )

    # user metadata bulk fetch with batches:

    try:
        UserMetadataRecipe.get_instance()
    except GeneralError:
        return send_200_response(
            DashboardUsersGetResponse(
                users_response.users, users_response.next_pagination_token
            ).to_json(),
            api_options.response,
        )

    updated_users_arr: List[Dict[str, Any]] = DashboardUsersGetResponse(
        users_response.users, users_response.next_pagination_token
    ).to_json()["users"]
    metadata_fetch_awaitables: List[Awaitable[Any]] = []

    async def get_user_metadata_and_update_user(user_idx: int) -> None:
        user = users_response.users[user_idx]
        user_metadata = await get_user_metadata(user.user_id)
        first_name = user_metadata.metadata.get("first_name")
        last_name = user_metadata.metadata.get("last_name")

        updated_users_arr[user_idx]["user"].update(
            {
                "firstName": first_name,
                "lastName": last_name,  # None becomes null which is acceptable for the dashboard.
            }
        )

    # Batch calls to get user metadata:
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

    return send_200_response(
        {
            "status": "OK",
            "users": updated_users_arr,
            "nextPaginationToken": users_response.next_pagination_token,
        },
        api_options.response,
    )
