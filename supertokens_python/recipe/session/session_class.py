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
from typing import Any, Dict, Union

from .interfaces import SessionContainer


class Session(SessionContainer):

    async def revoke_session(self, user_context: Union[Any, None] = None) -> None:
        if user_context is None:
            user_context = {}
        if await self.recipe_implementation.revoke_session(self.session_handle, user_context):
            self.remove_cookies = True

    async def get_session_data(self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        if user_context is None:
            user_context = {}
        session_info = await self.recipe_implementation.get_session_information(self.session_handle, user_context)
        return session_info.session_data

    async def update_session_data(self, new_session_data: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        if user_context is None:
            user_context = {}
        return await self.recipe_implementation.update_session_data(self.session_handle, new_session_data, user_context)

    async def update_access_token_payload(self, new_access_token_payload: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        if user_context is None:
            user_context = {}
        response = await self.recipe_implementation.regenerate_access_token(self.access_token, new_access_token_payload, user_context)
        self.access_token_payload = response.session.user_data_in_jwt
        if response.access_token is not None:
            self.access_token = response.access_token.token
            self.new_access_token_info = {
                'token': response.access_token.token,
                'expiry': response.access_token.expiry,
                'createdTime': response.access_token.created_time
            }

    def get_user_id(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.user_id

    def get_access_token_payload(
            self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        return self.access_token_payload

    def get_handle(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.session_handle

    def get_access_token(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.access_token

    async def get_time_created(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        if user_context is None:
            user_context = {}
        result = await self.recipe_implementation.get_session_information(self.session_handle, user_context)
        return result.time_created

    async def get_expiry(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        if user_context is None:
            user_context = {}
        result = await self.recipe_implementation.get_session_information(self.session_handle, user_context)
        return result.expiry
