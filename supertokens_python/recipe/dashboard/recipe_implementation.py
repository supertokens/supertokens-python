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
from supertokens_python.utils import log_debug_message, normalise_http_method
from supertokens_python.querier import Querier
from supertokens_python.recipe.dashboard.constants import (
    DASHBOARD_ANALYTICS_API,
    SIGN_OUT_API,
)

from .interfaces import RecipeInterface
from .utils import DashboardConfig, validate_api_key
from .exceptions import DashboardOperationNotAllowedError


class RecipeImplementation(RecipeInterface):
    async def get_dashboard_bundle_location(self, user_context: Dict[str, Any]) -> str:
        return f"https://cdn.jsdelivr.net/gh/supertokens/dashboard@v{DASHBOARD_VERSION}/build/"

    async def should_allow_access(
        self,
        request: BaseRequest,
        config: DashboardConfig,
        user_context: Dict[str, Any],
    ) -> bool:
        # For cases where we're not using the API key, the JWT is being used; we allow their access by default
        if config.api_key is None:
            auth_header_value = request.get_header("authorization")
            if not auth_header_value:
                return False

            auth_header_value = auth_header_value.split()[1]
            session_verification_response = (
                await Querier.get_instance().send_post_request(
                    NormalisedURLPath("/recipe/dashboard/session/verify"),
                    {"sessionId": auth_header_value},
                    user_context=user_context,
                )
            )
            if session_verification_response.get("status") != "OK":
                return False

            # For all non GET requests we also want to check if the
            # user is allowed to perform this operation
            if normalise_http_method(request.method()) != "get":
                # We dont want to block the analytics API
                if request.get_original_url().endswith(DASHBOARD_ANALYTICS_API):
                    return True

                # We do not want to block the sign out request
                if request.get_original_url().endswith(SIGN_OUT_API):
                    return True

                admins = config.admins

                if admins is None:
                    return True

                if len(admins) == 0:
                    log_debug_message(
                        "User Dashboard: Throwing OPERATION_NOT_ALLOWED because user is not an admin"
                    )
                    raise DashboardOperationNotAllowedError()

                user_email = session_verification_response.get("email")

                if user_email is None or not isinstance(user_email, str):
                    log_debug_message(
                        "User Dashboard: Returning UNAUTHORISED_ERROR because no email was provided in headers"
                    )
                    return False

                if user_email not in admins:
                    log_debug_message(
                        "User Dashboard: Throwing OPERATION_NOT_ALLOWED because user is not an admin"
                    )
                    raise DashboardOperationNotAllowedError()

            return True

        return await validate_api_key(request, config, user_context)
