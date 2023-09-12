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

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .utils import TokenTransferMethod

SESSION_REFRESH = "/session/refresh"
SIGNOUT = "/signout"
ACCESS_TOKEN_COOKIE_KEY = "sAccessToken"
REFRESH_TOKEN_COOKIE_KEY = "sRefreshToken"
FRONT_TOKEN_HEADER_SET_KEY = "front-token"
ANTI_CSRF_HEADER_KEY = "anti-csrf"
RID_HEADER_KEY = "rid"
AUTH_MODE_HEADER_KEY = "st-auth-mode"
AUTHORIZATION_HEADER_KEY = "authorization"
ACCESS_TOKEN_HEADER_KEY = "st-access-token"
REFRESH_TOKEN_HEADER_KEY = "st-refresh-token"
ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers"

available_token_transfer_methods: List[TokenTransferMethod] = ["cookie", "header"]

JWKCacheMaxAgeInMs = 60 * 1000  # 60s
protected_props = [
    "sub",
    "iat",
    "exp",
    "sessionHandle",
    "parentRefreshTokenHash1",
    "refreshTokenHash1",
    "antiCsrfToken",
    "rsub",
    "tId",
]
