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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.async_to_sync_wrapper import sync

from .utils import SessionConfig

from typing_extensions import Literal
if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse


class SessionObj:
    def __init__(self, handle: str, user_id: str, user_data_in_jwt: Dict[str, Any]):
        self.handle = handle
        self.user_id = user_id
        self.user_data_in_jwt = user_data_in_jwt


class AccessTokenObj:
    def __init__(self, token: str, expiry: int, created_time: int):
        self.token = token
        self.expiry = expiry
        self.created_time = created_time


class RegenerateAccessTokenResult(ABC):
    def __init__(self, status: Literal['OK'], session: SessionObj,
                 access_token: Union[AccessTokenObj, None]):
        self.status = status
        self.session = session
        self.access_token = access_token


class RegenerateAccessTokenOkResult(RegenerateAccessTokenResult):
    def __init__(self, session: SessionObj,
                 access_token: Union[AccessTokenObj, None]):
        super().__init__('OK', session, access_token)


class SessionInformationResult(ABC):
    def __init__(self, status: Literal['OK'], session_handle: str, user_id: str, session_data: Dict[str, Any], expiry: int, access_token_payload: Dict[str, Any], time_created: int):
        self.status: Literal['OK'] = status
        self.session_handle: str = session_handle
        self.user_id: str = user_id
        self.session_data: Dict[str, Any] = session_data
        self.expiry: int = expiry
        self.access_token_payload: Dict[str, Any] = access_token_payload
        self.time_created: int = time_created


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_new_session(self, request: Any, user_id: str,
                                 access_token_payload: Union[None, Dict[str, Any]],
                                 session_data: Union[None, Dict[str, Any]], user_context: Dict[str, Any]) -> SessionContainer:
        pass

    @abstractmethod
    async def get_session(self, request: Any, anti_csrf_check: Union[bool, None],
                          session_required: bool, user_context: Dict[str, Any]) -> Union[SessionContainer, None]:
        pass

    @abstractmethod
    async def refresh_session(self, request: Any, user_context: Dict[str, Any]) -> SessionContainer:
        pass

    @abstractmethod
    async def revoke_session(self, session_handle: str, user_context: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    async def revoke_all_sessions_for_user(self, user_id: str, user_context: Dict[str, Any]) -> List[str]:
        pass

    @abstractmethod
    async def get_all_session_handles_for_user(self, user_id: str, user_context: Dict[str, Any]) -> List[str]:
        pass

    @abstractmethod
    async def revoke_multiple_sessions(self, session_handles: List[str], user_context: Dict[str, Any]) -> List[str]:
        pass

    @abstractmethod
    async def get_session_information(self, session_handle: str, user_context: Dict[str, Any]) -> SessionInformationResult:
        pass

    @abstractmethod
    async def update_session_data(self, session_handle: str, new_session_data: Dict[str, Any], user_context: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    async def update_access_token_payload(self, session_handle: str,
                                          new_access_token_payload: Dict[str, Any], user_context: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    async def get_access_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        pass

    @abstractmethod
    async def get_refresh_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        pass

    @abstractmethod
    async def regenerate_access_token(self,
                                      access_token: str,
                                      new_access_token_payload: Union[Dict[str, Any], None], user_context: Dict[str, Any]) -> RegenerateAccessTokenResult:
        pass


class SignOutResponse:
    def __init__(self):
        pass

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        pass


class SignOutOkayResponse(SignOutResponse):
    def __init__(self):
        self.status = 'OK'
        super().__init__()

    def to_json(self) -> Dict[str, Any]:
        return {
            'status': self.status
        }


class APIOptions:
    def __init__(self, request: BaseRequest, response: Union[None, BaseResponse],
                 recipe_id: str, config: SessionConfig, recipe_implementation: RecipeInterface):
        self.request: BaseRequest = request
        self.response: Union[None, BaseResponse] = response
        self.recipe_id: str = recipe_id
        self.config: SessionConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation


class APIInterface(ABC):
    def __init__(self):
        self.disable_refresh_post = False
        self.disable_signout_post = False

    @abstractmethod
    async def refresh_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    async def signout_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> SignOutResponse:
        pass

    @abstractmethod
    async def verify_session(self, api_options: APIOptions,
                             anti_csrf_check: Union[bool, None],
                             session_required: bool, user_context: Dict[str, Any]) -> Union[SessionContainer, None]:
        pass


class SessionContainer(ABC):
    def __init__(self, recipe_implementation: RecipeInterface, access_token: str, session_handle: str, user_id: str, access_token_payload: Dict[str, Any]):
        self.recipe_implementation = recipe_implementation
        self.access_token = access_token
        self.session_handle = session_handle
        self.access_token_payload = access_token_payload
        self.user_id = user_id
        self.new_access_token_info = None
        self.new_refresh_token_info = None
        self.new_id_refresh_token_info = None
        self.new_anti_csrf_token = None
        self.remove_cookies = False

    @abstractmethod
    async def revoke_session(self, user_context: Union[Any, None] = None) -> None:
        pass

    @abstractmethod
    async def get_session_data(self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def update_session_data(self, new_session_data: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        pass

    @abstractmethod
    async def update_access_token_payload(self, new_access_token_payload: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        pass

    @abstractmethod
    def get_user_id(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        pass

    @abstractmethod
    def get_access_token_payload(
            self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_handle(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        pass

    @abstractmethod
    def get_access_token(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        pass

    @abstractmethod
    async def get_time_created(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        pass

    @abstractmethod
    async def get_expiry(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        pass

    def sync_get_expiry(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        return sync(self.get_expiry(user_context))

    def sync_revoke_session(
            self, user_context: Union[Dict[str, Any], None] = None) -> None:
        return sync(self.revoke_session(user_context=user_context))

    def sync_get_session_data(
            self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        return sync(self.get_session_data(user_context))

    def sync_get_time_created(
            self, user_context: Union[Dict[str, Any], None] = None) -> int:
        return sync(self.get_time_created(user_context))

    def sync_update_access_token_payload(
            self, new_access_token_payload: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        return sync(self.update_access_token_payload(new_access_token_payload, user_context))

    def sync_update_session_data(
            self, new_session_data: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        return sync(self.update_session_data(new_session_data, user_context))

    # This is there so that we can do session["..."] to access some of the members of this class
    def __getitem__(self, item: str):
        return getattr(self, item)
