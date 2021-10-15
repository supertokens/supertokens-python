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
from .jwt import get_payload
from supertokens_python.utils import get_timestamp_ms
from .exceptions import raise_try_refresh_token_exception
from typing import Union


def sanitize_string(s: any) -> Union[str, None]:
    if s == "":
        return s

    if not isinstance(s, str):
        return None

    return s.strip()


def sanitize_number(n: any) -> Union[Union[int, float], None]:
    _type = type(n)
    if _type == int or _type == float:
        return n

    return None


def get_info_from_access_token(
        token: str, jwt_signing_public_key: str, do_anti_csrf_check: bool):
    try:
        payload = get_payload(token, jwt_signing_public_key)
        session_handle = sanitize_string(payload.get('sessionHandle'))
        user_id = sanitize_string(payload.get('userId'))
        refresh_token_hash_1 = sanitize_string(
            payload.get('refreshTokenHash1'))
        parent_refresh_token_hash_1 = sanitize_string(
            payload.get('parentRefreshTokenHash1'))
        user_data = payload.get('userData')
        anti_csrf_token = sanitize_string(payload.get('antiCsrfToken'))
        expiry_time = sanitize_number(payload.get('expiryTime'))
        time_created = sanitize_number(payload.get('timeCreated'))

        if (session_handle is None) or \
                (user_data is None) or \
                (refresh_token_hash_1 is None) or \
                (user_data is None) or \
                (anti_csrf_token is None and do_anti_csrf_check) or \
                (expiry_time is None) or \
                (time_created is None):
            raise Exception(
                'Access token does not contain all the information. Maybe the structure has changed?')

        if expiry_time < get_timestamp_ms():
            raise Exception('Access token expired')

        return {
            'sessionHandle': session_handle,
            'userId': user_id,
            'refreshTokenHash1': refresh_token_hash_1,
            'parentRefreshTokenHash1': parent_refresh_token_hash_1,
            'userData': user_data,
            'antiCsrfToken': anti_csrf_token,
            'expiryTime': expiry_time,
            'timeCreated': time_created
        }
    except Exception as e:
        raise_try_refresh_token_exception(e)
