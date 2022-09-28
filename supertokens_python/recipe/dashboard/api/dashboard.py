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

from typing import TYPE_CHECKING, Optional

from supertokens_python.framework import BaseResponse

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )

from supertokens_python.utils import default_user_context


async def handle_dashboard_api(
    api_implementation: APIInterface, api_options: APIOptions
) -> Optional[BaseResponse]:
    if api_implementation.dashboard_get is None:
        return None

    user_context = default_user_context(api_options.request)
    html_str = await api_implementation.dashboard_get(api_options, user_context)

    api_options.response.set_html_content(html_str)
    return api_options.response
