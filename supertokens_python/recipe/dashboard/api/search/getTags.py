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

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.dashboard.interfaces import SearchTagsOK


async def handle_get_tags(
    _: APIInterface, _tenant_id: str, __: APIOptions, _user_context: Dict[str, Any]
) -> SearchTagsOK:
    response = await Querier.get_instance().send_get_request(
        NormalisedURLPath("/user/search/tags"), None, _user_context
    )
    return SearchTagsOK(tags=response["tags"])
