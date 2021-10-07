"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from typing import List, TYPE_CHECKING


if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import RecipeModule, APIHandled


class EmailVerificationRecipe(RecipeModule):
    recipe_id = 'jwt'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo):
        super().__init__(recipe_id, app_info)

    def is_error_from_this_or_child_recipe_based_on_instance(self, err):
        pass

    def get_apis_handled(self) -> List[APIHandled]:
        pass

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str,
                                 response: BaseResponse):
        pass

    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse):
        pass

    def get_all_cors_headers(self):
        pass
