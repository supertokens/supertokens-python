# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from abc import ABC
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse

    from .utils import OAuth2ProviderConfig


class RecipeInterface(ABC):
    def __init__(self):
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: OAuth2ProviderConfig,
        recipe_implementation: RecipeInterface,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: OAuth2ProviderConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation


class APIInterface:
    def __init__(self):
        pass
