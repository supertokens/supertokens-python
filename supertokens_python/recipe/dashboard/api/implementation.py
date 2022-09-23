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
from typing import TYPE_CHECKING, Any, Dict

from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python import Supertokens
from supertokens_python.normalised_url_path import NormalisedURLPath
from ..interfaces import (
    APIInterface,
)

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

            connection_uri = super_tokens_instance.supertokens_config.connection_uri

            return Template(
                """
                <html>
                    <head>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <script>
                            window.staticBasePath = "${bundleDomain}/static"
                            window.dashboardAppPath = "${input.options.appInfo.apiBasePath
                                .appendPath(new NormalisedURLPath(DASHBOARD_API))
                                .getAsStringDangerous()}"
                            window.connectionURI = "${connectionURI}"
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
            ).substitute(bundleDomain=bundle_domain, connectionURI=connection_uri)

        self.dashboard_get = dashboard_get
