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

from typing import List, Optional

from typing_extensions import Literal

from supertokens_python.recipe_module import RecipeModule
from supertokens_python.types import RecipeUserId

from .plugins import LoadPluginsResponse
from .supertokens import (
    AppInfo,
    InputAppInfo,
    RecipeInit,
    Supertokens,
    SupertokensConfig,
    SupertokensExperimentalConfig,
    SupertokensInputConfig,
    SupertokensPublicConfig,
    get_request_from_user_context,
)

# Some Pydantic models need a rebuild to resolve ForwardRefs
# Referencing imports here to prevent lint errors.
# Caveat: These will be available for import from this module directly.
RecipeModule  # type: ignore

# LoadPluginsResponse -> SupertokensPublicConfig
LoadPluginsResponse.model_rebuild()
# SupertokensInputConfig -> RecipeModule
SupertokensInputConfig.model_rebuild()


def init(
    app_info: InputAppInfo,
    framework: Literal["fastapi", "flask", "django"],
    supertokens_config: SupertokensConfig,
    recipe_list: List[RecipeInit],
    mode: Optional[Literal["asgi", "wsgi"]] = None,
    telemetry: Optional[bool] = None,
    debug: Optional[bool] = None,
    experimental: Optional[SupertokensExperimentalConfig] = None,
):
    return Supertokens.init(
        app_info,
        framework,
        supertokens_config,
        recipe_list,
        mode,
        telemetry,
        debug,
        experimental=experimental,
    )


def get_all_cors_headers() -> List[str]:
    return Supertokens.get_instance().get_all_cors_headers()


def convert_to_recipe_user_id(user_id: str) -> RecipeUserId:
    return RecipeUserId(user_id)


__all__ = [
    "AppInfo",
    "InputAppInfo",
    "RecipeInit",
    "RecipeUserId",
    "Supertokens",
    "SupertokensConfig",
    "SupertokensExperimentalConfig",
    "SupertokensPublicConfig",
    "convert_to_recipe_user_id",
    "get_all_cors_headers",
    "get_request_from_user_context",
    "init",
]
