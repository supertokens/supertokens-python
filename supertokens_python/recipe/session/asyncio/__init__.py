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
from typing import Any, Dict, List, Union

from supertokens_python.recipe.openid.interfaces import \
    GetOpenIdDiscoveryConfigurationResult
from supertokens_python.recipe.session.interfaces import (
    SessionContainer, SessionInformationResult)
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.utils import FRAMEWORKS

from ...jwt.interfaces import CreateJwtResult, GetJWKSResult


async def create_new_session(request: Any, user_id: str, access_token_payload: Union[Dict[str, Any], None] = None, session_data: Union[Dict[str, Any], None] = None, user_context: Union[None, Dict[str, Any]] = None) -> SessionContainer:
    if user_context is None:
        user_context = {}
    if not hasattr(request, 'wrapper_used') or not request.wrapper_used:
        request = FRAMEWORKS[SessionRecipe.get_instance(
        ).app_info.framework].wrap_request(request)
    return await SessionRecipe.get_instance().recipe_implementation.create_new_session(request, user_id, access_token_payload, session_data, user_context=user_context)


async def get_session(request: Any, anti_csrf_check: Union[bool, None] = None, session_required: bool = True, user_context: Union[None, Dict[str, Any]] = None) -> Union[SessionContainer, None]:
    if user_context is None:
        user_context = {}
    if not hasattr(request, 'wrapper_used') or not request.wrapper_used:
        request = FRAMEWORKS[SessionRecipe.get_instance(
        ).app_info.framework].wrap_request(request)
    return await SessionRecipe.get_instance().recipe_implementation.get_session(request, anti_csrf_check, session_required, user_context)


async def refresh_session(request: Any, user_context: Union[None, Dict[str, Any]] = None) -> SessionContainer:
    if user_context is None:
        user_context = {}
    if not hasattr(request, 'wrapper_used') or not request.wrapper_used:
        request = FRAMEWORKS[SessionRecipe.get_instance(
        ).app_info.framework].wrap_request(request)
    return await SessionRecipe.get_instance().recipe_implementation.refresh_session(request, user_context)


async def revoke_session(session_handle: str, user_context: Union[None, Dict[str, Any]] = None) -> bool:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.revoke_session(session_handle, user_context)


async def revoke_all_sessions_for_user(user_id: str, user_context: Union[None, Dict[str, Any]] = None) -> List[str]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.revoke_all_sessions_for_user(user_id, user_context)


async def get_all_session_handles_for_user(user_id: str, user_context: Union[None, Dict[str, Any]] = None) -> List[str]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.get_all_session_handles_for_user(user_id, user_context)


async def revoke_multiple_sessions(session_handles: List[str], user_context: Union[None, Dict[str, Any]] = None) -> List[str]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.revoke_multiple_sessions(session_handles, user_context)


async def get_session_information(session_handle: str, user_context: Union[None, Dict[str, Any]] = None) -> SessionInformationResult:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.get_session_information(session_handle, user_context)


async def update_session_data(session_handle: str, new_session_data: Dict[str, Any], user_context: Union[None, Dict[str, Any]] = None) -> None:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.update_session_data(session_handle, new_session_data, user_context)


async def update_access_token_payload(session_handle: str, new_access_token_payload: Dict[str, Any], user_context: Union[None, Dict[str, Any]] = None) -> None:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.update_access_token_payload(session_handle, new_access_token_payload, user_context)


async def create_jwt(payload: Dict[str, Any], validity_seconds: Union[None, int] = None, user_context: Union[None, Dict[str, Any]] = None) -> CreateJwtResult:
    if user_context is None:
        user_context = {}
    openid_recipe = SessionRecipe.get_instance().openid_recipe

    if openid_recipe is not None:
        return await openid_recipe.recipe_implementation.create_jwt(payload, validity_seconds, user_context=user_context)

    raise Exception('create_jwt cannot be used without enabling the JWT feature. Please set \'enable: True\' for jwt config when initialising the Session recipe')


async def get_jwks(user_context: Union[None, Dict[str, Any]] = None) -> GetJWKSResult:
    if user_context is None:
        user_context = {}
    openid_recipe = SessionRecipe.get_instance().openid_recipe
    if openid_recipe is not None:
        return await openid_recipe.recipe_implementation.get_jwks(user_context)

    raise Exception('get_jwks cannot be used without enabling the JWT feature. Please set \'enable: True\' for jwt config when initialising the Session recipe')


async def get_open_id_discovery_configuration(user_context: Union[None, Dict[str, Any]] = None) -> GetOpenIdDiscoveryConfigurationResult:
    if user_context is None:
        user_context = {}
    openid_recipe = SessionRecipe.get_instance().openid_recipe

    if openid_recipe is not None:
        return await openid_recipe.recipe_implementation.get_open_id_discovery_configuration(
            user_context)

    raise Exception('get_open_id_discovery_configuration cannot be used without enabling the JWT feature. Please set \'enable: True\' for jwt config when initialising the Session recipe')


async def regenerate_access_token(access_token: str, new_access_token_payload: Union[Dict[str, Any], None] = None, user_context: Union[None, Dict[str, Any]] = None):
    if user_context is None:
        user_context = {}
    await SessionRecipe.get_instance().recipe_implementation.regenerate_access_token(access_token, new_access_token_payload, user_context)
