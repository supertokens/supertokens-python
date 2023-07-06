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

from typing import Any, Dict

from supertokens_python.constants import DASHBOARD_VERSION
from supertokens_python.framework import BaseRequest
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

from .interfaces import RecipeInterface
from .utils import DashboardConfig, validate_api_key


class RecipeImplementation(RecipeInterface):
    async def get_dashboard_bundle_location(self, user_context: Dict[str, Any]) -> str:
        return f"https://cdn.jsdelivr.net/gh/supertokens/dashboard@v{DASHBOARD_VERSION}/build/"

    async def should_allow_access(
        self,
        request: BaseRequest,
        config: DashboardConfig,
        user_context: Dict[str, Any],
    ) -> bool:
        if config.auth_mode == "email-password":
            auth_header_value = request.get_header("authorization")

            if not auth_header_value:
                return False

            auth_header_value = auth_header_value.split()[1]
            session_verification_response = (
                await Querier.get_instance().send_post_request(
                    NormalisedURLPath("/recipe/dashboard/session/verify"),
                    {"sessionId": auth_header_value},
                )
            )
            return (
                "status" in session_verification_response
                and session_verification_response["status"] == "OK"
            )
        return validate_api_key(request, config)
