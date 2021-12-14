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
from typing import Union, Literal

from .session_class import Session
from .recipe import SessionRecipe
from . import exceptions
from .utils import InputErrorHandlers, InputOverrideConfig, JWTConfig
from supertokens_python.recipe.openid import InputOverrideConfig as OpenIdInputOverrideConfig, JWTOverrideConfig


def init(cookie_domain: Union[str, None] = None,
         cookie_secure: Union[str, None] = None,
         cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
         session_expired_status_code: Union[str, None] = None,
         anti_csrf: Union[Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None] = None,
         error_handlers: Union[InputErrorHandlers, None] = None,
         override: Union[InputOverrideConfig, None] = None,
         jwt: Union[JWTConfig, None] = None):
    return SessionRecipe.init(cookie_domain,
                              cookie_secure,
                              cookie_same_site,
                              session_expired_status_code,
                              anti_csrf,
                              error_handlers,
                              override,
                              jwt)
