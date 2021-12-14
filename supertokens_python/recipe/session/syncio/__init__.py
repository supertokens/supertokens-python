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

from typing import Union, List

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.openid.interfaces import CreateJwtResult, GetOpenIdDiscoveryConfigurationResult, \
    GetJWKSResult
from supertokens_python.recipe.session.asyncio import Session


def create_new_session(request, user_id: str, access_token_payload: Union[dict, None] = None,
                       session_data: Union[dict, None] = None):
    from supertokens_python.recipe.session.asyncio import create_new_session as async_create_new_session
    return sync(async_create_new_session(
        request, user_id, access_token_payload, session_data))


def get_session(request, anti_csrf_check: Union[bool, None] = None, session_required: bool = True) -> Union[Session,
                                                                                                            None]:
    from supertokens_python.recipe.session.asyncio import get_session as async_get_session
    return sync(async_get_session(request, anti_csrf_check, session_required))


def refresh_session(request) -> Session:
    from supertokens_python.recipe.session.asyncio import refresh_session as async_refresh_session
    return sync(async_refresh_session(request))


def revoke_session(session_handle: str) -> bool:
    from supertokens_python.recipe.session.asyncio import revoke_session as async_revoke_session
    return sync(async_revoke_session(session_handle))


def revoke_all_sessions_for_user(user_id: str) -> List[str]:
    from supertokens_python.recipe.session.asyncio import revoke_all_sessions_for_user as async_revoke_all_sessions_for_user
    return sync(async_revoke_all_sessions_for_user(user_id))


def revoke_multiple_sessions(session_handles: List[str]) -> List[str]:
    from supertokens_python.recipe.session.asyncio import revoke_multiple_sessions as async_revoke_multiple_sessions
    return sync(async_revoke_multiple_sessions(session_handles))


def get_session_information(session_handle: str) -> dict:
    from supertokens_python.recipe.session.asyncio import get_session_information as async_get_session_information
    return sync(async_get_session_information(session_handle))


def update_session_data(session_handle: str, new_session_data: dict) -> None:
    from supertokens_python.recipe.session.asyncio import update_session_data as async_update_session_data
    return sync(async_update_session_data(session_handle, new_session_data))


async def update_access_token_payload(session_handle: str, new_access_token_payload: dict) -> None:
    from supertokens_python.recipe.session.asyncio import update_access_token_payload as async_update_access_token_payload
    return sync(async_update_access_token_payload(session_handle, new_access_token_payload))


async def create_jwt(payload: dict, validity_seconds: int = None) -> [CreateJwtResult, None]:
    from supertokens_python.recipe.session.asyncio import \
        create_jwt as async_create_jwt
    return sync(async_create_jwt(payload, validity_seconds))


async def get_jwks() -> [GetJWKSResult, None]:
    from supertokens_python.recipe.session.asyncio import \
        get_jwks as async_get_jwks
    return sync(async_get_jwks())


async def get_open_id_discovery_configuration() -> [GetOpenIdDiscoveryConfigurationResult, None]:
    from supertokens_python.recipe.session.asyncio import \
        get_open_id_discovery_configuration as async_get_open_id_discovery_configuration
    return sync(async_get_open_id_discovery_configuration())
