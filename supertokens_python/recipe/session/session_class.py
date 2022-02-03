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
from typing import TYPE_CHECKING, Union
from supertokens_python.async_to_sync_wrapper import sync

if TYPE_CHECKING:
    from .recipe_implementation import RecipeImplementation


class Session:
    def __init__(self, recipe_implementation: RecipeImplementation, access_token, session_handle, user_id,
                 access_token_payload):
        super().__init__()
        self.__recipe_implementation = recipe_implementation
        self.__access_token = access_token
        self.__session_handle = session_handle
        self.access_token_payload = access_token_payload
        self.user_id = user_id
        self.new_access_token_info = None
        self.new_refresh_token_info = None
        self.new_id_refresh_token_info = None
        self.new_anti_csrf_token = None
        self.remove_cookies = False

    async def revoke_session(self, user_context: Union[any, None] = None) -> None:
        if user_context is None:
            user_context = {}
        if await self.__recipe_implementation.revoke_session(self.__session_handle, user_context):
            self.remove_cookies = True

    def sync_revoke_session(
            self, user_context: Union[any, None] = None) -> None:
        sync(self.revoke_session(user_context))

    def sync_get_session_data(
            self, user_context: Union[any, None] = None) -> dict:
        return sync(self.get_session_data(user_context))

    async def get_session_data(self, user_context: Union[any, None] = None) -> dict:
        if user_context is None:
            user_context = {}
        session_info = await self.__recipe_implementation.get_session_information(self.__session_handle, user_context)
        return session_info['sessionData']

    def sync_update_session_data(
            self, new_session_data, user_context: Union[any, None] = None) -> None:
        sync(self.update_session_data(new_session_data, user_context))

    async def update_session_data(self, new_session_data, user_context: Union[any, None] = None) -> None:
        if user_context is None:
            user_context = {}
        return await self.__recipe_implementation.update_session_data(self.__session_handle, new_session_data, user_context)

    def sync_update_access_token_payload(
            self, new_access_token_payload, user_context: Union[any, None] = None) -> None:
        sync(
            self.update_access_token_payload(
                new_access_token_payload,
                user_context))

    async def update_access_token_payload(self, new_access_token_payload, user_context: Union[any, None] = None) -> None:
        if user_context is None:
            user_context = {}
        response = await self.__recipe_implementation.regenerate_access_token(self.__access_token, user_context, new_access_token_payload)
        self.access_token_payload = response.session.user_data_in_jwt
        if response.access_token is not None:
            self.__access_token = response.access_token.token
            self.new_access_token_info = {
                'token': response.access_token.token,
                'expiry': response.access_token.expiry,
                'createdTime': response.access_token.created_time
            }

    def get_user_id(self, user_context: Union[any, None] = None) -> str:
        return self.user_id

    def get_access_token_payload(
            self, user_context: Union[any, None] = None) -> dict:
        return self.access_token_payload

    def get_handle(self, user_context: Union[any, None] = None) -> str:
        return self.__session_handle

    def get_access_token(self, user_context: Union[any, None] = None) -> str:
        return self.__access_token

    async def get_time_created(self, user_context: Union[any, None] = None):
        if user_context is None:
            user_context = {}
        result = await self.__recipe_implementation.get_session_information(self.__session_handle, user_context)
        return result['timeCreated']

    def sync_get_time_created(
            self, user_context: Union[any, None] = None) -> dict:
        return sync(self.get_time_created(user_context))

    async def get_expiry(self, user_context: Union[any, None] = None):
        if user_context is None:
            user_context = {}
        result = await self.__recipe_implementation.get_session_information(self.__session_handle, user_context)
        return result['expiry']

    def sync_get_expiry(self, user_context: Union[any, None] = None) -> dict:
        return sync(self.get_expiry(user_context))

    def __getitem__(self, item):
        return getattr(self, item)
