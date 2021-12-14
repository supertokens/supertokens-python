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

from supertokens_python.recipe.openid.interfaces import CreateJwtResult, GetJWKSResult, \
    GetOpenIdDiscoveryConfigurationResult
from supertokens_python.recipe.session.session_class import Session
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.utils import FRAMEWORKS


async def create_new_session(request, user_id: str, access_token_payload: Union[dict, None] = None,
                             session_data: Union[dict, None] = None) -> Session:
    if not hasattr(request, 'wrapper_used') or not request.wrapper_used:
        request = FRAMEWORKS[SessionRecipe.get_instance(
        ).app_info.framework].wrap_request(request)
    return await SessionRecipe.get_instance().recipe_implementation.create_new_session(request, user_id, access_token_payload,
                                                                                       session_data)


async def get_session(request, anti_csrf_check: Union[bool, None] = None, session_required: bool = True) -> Union[
        SessionRecipe, None]:
    if not hasattr(request, 'wrapper_used') or not request.wrapper_used:
        request = FRAMEWORKS[SessionRecipe.get_instance(
        ).app_info.framework].wrap_request(request)
    return await SessionRecipe.get_instance().recipe_implementation.get_session(request, anti_csrf_check,
                                                                                session_required)


async def refresh_session(request) -> Session:
    if not hasattr(request, 'wrapper_used') or not request.wrapper_used:
        request = FRAMEWORKS[SessionRecipe.get_instance(
        ).app_info.framework].wrap_request(request)
    return await SessionRecipe.get_instance().recipe_implementation.refresh_session(request)


async def revoke_session(session_handle: str) -> bool:
    return await SessionRecipe.get_instance().recipe_implementation.revoke_session(session_handle)


async def revoke_all_sessions_for_user(user_id: str) -> List[str]:
    return await SessionRecipe.get_instance().recipe_implementation.revoke_all_sessions_for_user(user_id)


async def get_all_session_handles_for_user(user_id: str) -> List[str]:
    return await SessionRecipe.get_instance().recipe_implementation.get_all_session_handles_for_user(user_id)


async def revoke_multiple_sessions(session_handles: List[str]) -> List[str]:
    return await SessionRecipe.get_instance().recipe_implementation.revoke_multiple_sessions(session_handles)


async def get_session_information(session_handle: str) -> dict:
    return await SessionRecipe.get_instance().recipe_implementation.get_session_information(session_handle)


async def update_session_data(session_handle: str, new_session_data: dict) -> None:
    return await SessionRecipe.get_instance().recipe_implementation.update_session_data(session_handle,
                                                                                        new_session_data)


async def update_access_token_payload(session_handle: str, new_access_token_payload: dict) -> None:
    return await SessionRecipe.get_instance().recipe_implementation.update_access_token_payload(session_handle, new_access_token_payload)


async def create_jwt(payload: dict, validity_seconds: int = None) -> [CreateJwtResult, None]:
    openid_recipe = SessionRecipe.get_instance().openid_recipe

    if openid_recipe is not None:
        return await openid_recipe.recipe_implementation.create_jwt(payload, validity_seconds)

    raise 'create_jwt cannot be used without enabling the JWT feature. Please set \'enable: True\' for jwt config ' \
          'when initialising the Session recipe'


async def get_jwks() -> [GetJWKSResult, None]:
    openid_recipe = SessionRecipe.get_instance().openid_recipe

    if openid_recipe is not None:
        return openid_recipe.recipe_implementation.get_jwks()

    raise 'get_jwks cannot be used without enabling the JWT feature. Please set \'enable: True\' for jwt config ' \
          'when initialising the Session recipe'


async def get_open_id_discovery_configuration() -> [GetOpenIdDiscoveryConfigurationResult, None]:
    openid_recipe = SessionRecipe.get_instance().openid_recipe

    if openid_recipe is not None:
        return openid_recipe.recipe_implementation.get_open_id_discovery_configuration()

    raise 'get_open_id_discovery_configuration cannot be used without enabling the JWT feature. Please set \'enable: ' \
          'True\' for jwt config when initialising the Session recipe'
