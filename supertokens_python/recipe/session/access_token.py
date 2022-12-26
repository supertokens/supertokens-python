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

from typing import Any, Dict, Union

from supertokens_python.logger import log_debug_message
from supertokens_python.utils import get_timestamp_ms

from .exceptions import raise_try_refresh_token_exception
from .jwt import ParsedJWTInfo, verify_jwt


def sanitize_string(s: Any) -> Union[str, None]:
    if s == "":
        return s

    if not isinstance(s, str):
        return None

    return s.strip()


def sanitize_number(n: Any) -> Union[Union[int, float], None]:
    _type = type(n)
    if _type == int or _type == float:  # pylint: disable=consider-using-in
        return n

    return None


def get_info_from_access_token(
    jwt_info: ParsedJWTInfo, jwt_signing_public_key: str, do_anti_csrf_check: bool
):
    try:
        verify_jwt(jwt_info, jwt_signing_public_key)
        payload = jwt_info.payload

        validate_access_token_structure(payload)

        session_handle = sanitize_string(payload.get("sessionHandle"))
        user_id = sanitize_string(payload.get("userId"))
        refresh_token_hash_1 = sanitize_string(payload.get("refreshTokenHash1"))
        parent_refresh_token_hash_1 = sanitize_string(
            payload.get("parentRefreshTokenHash1")
        )
        user_data = payload.get("userData")
        anti_csrf_token = sanitize_string(payload.get("antiCsrfToken"))
        expiry_time = sanitize_number(payload.get("expiryTime"))
        time_created = sanitize_number(payload.get("timeCreated"))

        if anti_csrf_token is None and do_anti_csrf_check:
            raise Exception("Access token does not contain the anti-csrf token")

        assert isinstance(expiry_time, int)

        if expiry_time < get_timestamp_ms():
            raise Exception("Access token expired")

        return {
            "sessionHandle": session_handle,
            "userId": user_id,
            "refreshTokenHash1": refresh_token_hash_1,
            "parentRefreshTokenHash1": parent_refresh_token_hash_1,
            "userData": user_data,
            "antiCsrfToken": anti_csrf_token,
            "expiryTime": expiry_time,
            "timeCreated": time_created,
        }
    except Exception as e:
        log_debug_message(
            "getSession: Returning TRY_REFRESH_TOKEN because failed to decode access token"
        )
        raise_try_refresh_token_exception(e)


def validate_access_token_structure(payload: Dict[str, Any]) -> None:
    if (
        not isinstance(payload.get("sessionHandle"), str)
        or payload.get("userData") is None
        or not isinstance(payload.get("refreshTokenHash1"), str)
        or not isinstance(payload.get("expiryTime"), int)
        or not isinstance(payload.get("timeCreated"), int)
    ):
        raise Exception(
            "Access token does not contain all the information. Maybe the structure has changed?"
        )
