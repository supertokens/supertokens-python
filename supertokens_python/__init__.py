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

from typing import Any, Callable, Dict, List, Optional

from typing_extensions import Literal

from supertokens_python.framework.request import BaseRequest

from . import supertokens
from .recipe_module import RecipeModule

InputAppInfo = supertokens.InputAppInfo
Supertokens = supertokens.Supertokens
SupertokensConfig = supertokens.SupertokensConfig
AppInfo = supertokens.AppInfo


def init(
    app_info: InputAppInfo,
    framework: Literal["fastapi", "flask", "django"],
    supertokens_config: SupertokensConfig,
    recipe_list: List[Callable[[supertokens.AppInfo], RecipeModule]],
    mode: Optional[Literal["asgi", "wsgi"]] = None,
    telemetry: Optional[bool] = None,
    debug: Optional[bool] = None,
):
    return Supertokens.init(
        app_info, framework, supertokens_config, recipe_list, mode, telemetry, debug
    )


def get_all_cors_headers() -> List[str]:
    return supertokens.Supertokens.get_instance().get_all_cors_headers()


def get_request_from_user_context(
    user_context: Optional[Dict[str, Any]],
) -> Optional[BaseRequest]:
    return Supertokens.get_instance().get_request_from_user_context(user_context)
