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

from typing import TYPE_CHECKING, Dict, Any

from httpx import AsyncClient

from supertokens_python import Supertokens
from supertokens_python.constants import (
    TELEMETRY_SUPERTOKENS_API_URL,
    TELEMETRY_SUPERTOKENS_API_VERSION,
)
from supertokens_python.constants import VERSION as SDKVersion
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

from ..interfaces import AnalyticsResponse

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions


async def handle_analytics_post(
    _: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    _user_context: Dict[str, Any],
) -> AnalyticsResponse:
    if not Supertokens.get_instance().telemetry:
        return AnalyticsResponse()
    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please send body")
    email = body.get("email")
    dashboard_version = body.get("dashboardVersion")

    if email is None:
        raise_bad_input_exception("Missing required property 'email'")
    if dashboard_version is None:
        raise_bad_input_exception("Missing required property 'dashboardVersion'")

    telemetry_id = None

    try:
        response = await Querier.get_instance().send_get_request(
            NormalisedURLPath("/telemetry"),
            None,
            _user_context,
        )
        if "exists" in response and response["exists"] and "telemetryId" in response:
            telemetry_id = response["telemetryId"]

        number_of_users = await Supertokens.get_instance().get_user_count(
            include_recipe_ids=None
        )

    except Exception as __:
        # If either telemetry id API or user count fetch fails, no event should be sent
        return AnalyticsResponse()

    apiDomain, websiteDomain, appName = (
        api_options.app_info.api_domain,
        api_options.app_info.get_origin(api_options.request, {}),
        api_options.app_info.app_name,
    )

    data = {
        "websiteDomain": websiteDomain.get_as_string_dangerous(),
        "apiDomain": apiDomain.get_as_string_dangerous(),
        "appName": appName,
        "sdk": "python",
        "sdkVersion": SDKVersion,
        "numberOfUsers": number_of_users,
        "email": email,
        "dashboardVersion": dashboard_version,
    }

    if telemetry_id is not None:
        data["telemetryId"] = telemetry_id

    try:
        async with AsyncClient() as client:
            await client.post(  # type: ignore
                url=TELEMETRY_SUPERTOKENS_API_URL,
                json=data,
                headers={"api-version": TELEMETRY_SUPERTOKENS_API_VERSION},
            )
    except Exception as __:
        # If telemetry event fails, no error should be thrown
        pass

    return AnalyticsResponse()
