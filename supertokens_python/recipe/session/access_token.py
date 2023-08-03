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

from typing import Any, Dict, Optional, Union

import jwt
from jwt.exceptions import DecodeError

from supertokens_python.logger import log_debug_message
from supertokens_python.utils import get_timestamp_ms

from .exceptions import raise_try_refresh_token_exception
from .jwt import ParsedJWTInfo

from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID


def sanitize_string(s: Any) -> Union[str, None]:
    if s == "":
        return s

    if not isinstance(s, str):
        return None

    return s.strip()


def sanitize_number(n: Any) -> Union[Union[int, float], None]:
    if isinstance(n, (int, float)):
        return n

    return None


from supertokens_python.recipe.session.jwks import get_latest_keys


def get_info_from_access_token(
    jwt_info: ParsedJWTInfo,
    do_anti_csrf_check: bool,
):
    try:
        payload: Optional[Dict[str, Any]] = None
        decode_algo = (
            jwt_info.parsed_header["alg"]
            if jwt_info.parsed_header is not None
            else "RS256"
        )

        if jwt_info.version >= 3:
            matching_keys = get_latest_keys(jwt_info.kid)
            payload = jwt.decode(  # type: ignore
                jwt_info.raw_token_string,
                matching_keys[0].key,  # type: ignore
                algorithms=[decode_algo],
                options={"verify_signature": True, "verify_exp": True},
            )
        else:
            # It won't have kid. So we'll have to try the token against all the keys from all the jwk_clients
            # If any of them work, we'll use that payload
            for k in get_latest_keys():
                try:
                    payload = jwt.decode(  # type: ignore
                        jwt_info.raw_token_string,
                        k.key,  # type: ignore
                        algorithms=[decode_algo],
                        options={"verify_signature": True, "verify_exp": True},
                    )
                    break
                except DecodeError:
                    pass

        if payload is None:
            raise DecodeError("Could not decode the token")

        validate_access_token_structure(payload, jwt_info.version)

        if jwt_info.version == 2:
            user_id = sanitize_string(payload.get("userId"))
            expiry_time = sanitize_number(payload.get("expiryTime"))
            time_created = sanitize_number(payload.get("timeCreated"))
            user_data = payload.get("userData")
        else:
            user_id = sanitize_string(payload.get("sub"))
            expiry_time = sanitize_number(payload.get("exp", 0) * 1000)
            time_created = sanitize_number(payload.get("iat", 0) * 1000)
            user_data = payload

        session_handle = sanitize_string(payload.get("sessionHandle"))
        refresh_token_hash_1 = sanitize_string(payload.get("refreshTokenHash1"))
        parent_refresh_token_hash_1 = sanitize_string(
            payload.get("parentRefreshTokenHash1")
        )
        anti_csrf_token = sanitize_string(payload.get("antiCsrfToken"))
        tenant_id = DEFAULT_TENANT_ID

        if jwt_info.version >= 4:
            tenant_id = sanitize_string(payload.get("tId"))

        if anti_csrf_token is None and do_anti_csrf_check:
            raise Exception("Access token does not contain the anti-csrf token")

        assert isinstance(expiry_time, (float, int))

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
            "tenantId": tenant_id,
        }
    except Exception as e:
        log_debug_message(
            "getInfoFromAccessToken: Returning TRY_REFRESH_TOKEN because access token validation failed - %s",
            e,
        )
        raise_try_refresh_token_exception(e)


def validate_access_token_structure(payload: Dict[str, Any], version: int) -> None:
    if version >= 3:
        if (
            not isinstance(payload.get("sub"), str)
            or not isinstance(payload.get("exp"), (int, float))
            or not isinstance(payload.get("iat"), (int, float))
            or not isinstance(payload.get("sessionHandle"), str)
            or not isinstance(payload.get("refreshTokenHash1"), str)
        ):
            log_debug_message(
                "validateAccessTokenStructure: Access token is using version >= 3"
            )
            # The error message below will be logged by the error handler that translates this into a TRY_REFRESH_TOKEN_ERROR
            raise Exception(
                "Access token does not contain all the information. Maybe the structure has changed?"
            )

        if version >= 4:
            if not isinstance(payload.get("tId"), str):
                raise Exception(
                    "Access token does not contain all the information. Maybe the structure has changed?"
                )

    elif (
        not isinstance(payload.get("sessionHandle"), str)
        or payload.get("userData") is None
        or not isinstance(payload.get("refreshTokenHash1"), str)
        or not isinstance(payload.get("expiryTime"), (float, int))
        or not isinstance(payload.get("timeCreated"), (float, int))
    ):
        log_debug_message(
            "validateAccessTokenStructure: Access token is using version < 3"
        )
        # The error message below will be logged by the error handler that translates this into a TRY_REFRESH_TOKEN_ERROR
        raise Exception(
            "Access token does not contain all the information. Maybe the structure has changed?"
        )
