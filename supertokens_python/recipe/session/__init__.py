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

from typing import TYPE_CHECKING, Callable, Union

from typing_extensions import Literal

if TYPE_CHECKING:
    from ...recipe_module import RecipeModule
    from supertokens_python.supertokens import AppInfo

from . import exceptions as ex
from .recipe import SessionRecipe
from . import utils
from . import interfaces

InputErrorHandlers = utils.InputErrorHandlers
InputOverrideConfig = utils.InputOverrideConfig
JWTConfig = utils.JWTConfig
SessionContainer = interfaces.SessionContainer
exceptions = ex


def init(
    cookie_domain: Union[str, None] = None,
    cookie_secure: Union[bool, None] = None,
    cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
    session_expired_status_code: Union[int, None] = None,
    anti_csrf: Union[Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None] = None,
    error_handlers: Union[InputErrorHandlers, None] = None,
    override: Union[InputOverrideConfig, None] = None,
    jwt: Union[JWTConfig, None] = None,
    invalid_claim_status_code: Union[int, None] = None,
) -> Callable[[AppInfo], RecipeModule]:
    return SessionRecipe.init(
        cookie_domain,
        cookie_secure,
        cookie_same_site,
        session_expired_status_code,
        anti_csrf,
        error_handlers,
        override,
        jwt,
        invalid_claim_status_code,
    )
