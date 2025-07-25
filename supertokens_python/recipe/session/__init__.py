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

from typing import TYPE_CHECKING, Any, Callable, Dict, Union

from typing_extensions import Literal

from supertokens_python.framework import BaseRequest

from .interfaces import SessionContainer
from .recipe import SessionRecipe
from .utils import (
    InputErrorHandlers,
    InputOverrideConfig,
    SessionOverrideConfig,
    TokenTransferMethod,
)

if TYPE_CHECKING:
    from supertokens_python.supertokens import RecipeInit


def init(
    cookie_domain: Union[str, None] = None,
    older_cookie_domain: Union[str, None] = None,
    cookie_secure: Union[bool, None] = None,
    cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
    session_expired_status_code: Union[int, None] = None,
    anti_csrf: Union[Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None] = None,
    get_token_transfer_method: Union[
        Callable[
            [BaseRequest, bool, Dict[str, Any]],
            Union[TokenTransferMethod, Literal["any"]],
        ],
        None,
    ] = None,
    error_handlers: Union[InputErrorHandlers, None] = None,
    override: Union[SessionOverrideConfig, None] = None,
    invalid_claim_status_code: Union[int, None] = None,
    use_dynamic_access_token_signing_key: Union[bool, None] = None,
    expose_access_token_to_frontend_in_cookie_based_auth: Union[bool, None] = None,
    jwks_refresh_interval_sec: Union[int, None] = None,
) -> RecipeInit:
    return SessionRecipe.init(
        cookie_domain,
        older_cookie_domain,
        cookie_secure,
        cookie_same_site,
        session_expired_status_code,
        anti_csrf,
        get_token_transfer_method,
        error_handlers,
        override,
        invalid_claim_status_code,
        use_dynamic_access_token_signing_key,
        expose_access_token_to_frontend_in_cookie_based_auth,
        jwks_refresh_interval_sec,
    )


__all__ = [
    "InputErrorHandlers",
    "InputOverrideConfig",  # deprecated, use SessionOverrideConfig instead
    "SessionContainer",
    "SessionOverrideConfig",
    "SessionRecipe",
    "TokenTransferMethod",
    "init",
]
