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

from string import Template
from textwrap import dedent
from typing import TYPE_CHECKING, Any, Dict

from supertokens_python import Supertokens
from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.utils import is_version_gte

from ..constants import DASHBOARD_API
from ..interfaces import APIInterface

if TYPE_CHECKING:
    from ..interfaces import APIOptions


class APIImplementation(APIInterface):
    def __init__(self):
        super().__init__()

        async def dashboard_get(
            options: APIOptions, user_context: Dict[str, Any]
        ) -> str:
            bundle_base_path_string = (
                await options.recipe_implementation.get_dashboard_bundle_location(
                    user_context
                )
            )
            bundle_domain = (
                NormalisedURLDomain(bundle_base_path_string).get_as_string_dangerous()
                + NormalisedURLPath(bundle_base_path_string).get_as_string_dangerous()
            )

            connection_uri = ""
            super_tokens_instance = Supertokens.get_instance()
            auth_mode = options.config.auth_mode
            connection_uri = super_tokens_instance.supertokens_config.connection_uri

            dashboard_path = options.app_info.api_base_path.append(
                NormalisedURLPath(DASHBOARD_API)
            ).get_as_string_dangerous()

            is_search_enabled: bool = False
            querier = Querier.get_instance(options.recipe_id)
            cdiVersion = await querier.get_api_version()
            if not cdiVersion:
                is_search_enabled = True
            elif is_version_gte(cdiVersion, "2.20"):
                is_search_enabled = True

            return Template(
                dedent(
                    """
                <html>
                    <head>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <script>
                            window.staticBasePath = "${bundleDomain}/static"
                            window.dashboardAppPath = "${dashboardPath}"
                            window.connectionURI = "${connectionURI}"
                            window.authMode = "${authMode}"
                            window.isSearchEnabled = "${isSearchEnabled}"
                        </script>
                        <script defer src="${bundleDomain}/static/js/bundle.js"></script></head>
                        <link href="${bundleDomain}/static/css/main.css" rel="stylesheet" type="text/css">
                        <link rel="icon" type="image/x-icon" href="${bundleDomain}/static/media/favicon.ico">
                    </head>
                    <body>
                        <noscript>You need to enable JavaScript to run this app.</noscript>
                        <div id="root"></div>
                    </body>
                </html>
                """
                )
            ).substitute(
                bundleDomain=bundle_domain,
                dashboardPath=dashboard_path,
                connectionURI=connection_uri,
                authMode=auth_mode,
                isSearchEnabled=str(is_search_enabled).lower(),
            )

        self.dashboard_get = dashboard_get
