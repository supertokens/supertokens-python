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
from typing import Union, List, TYPE_CHECKING
if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.jwt.interfaces import RecipeInterface as JWTRecipeInterface
    from .utils import SessionConfig
    from .session_class import Session


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def create_new_session(self, request: any, user_id: str, access_token_payload: Union[dict, None] = None,
                                 session_data: Union[dict, None] = None) -> Session:
        pass

    @abstractmethod
    async def get_session(self, request: any, anti_csrf_check: Union[bool, None] = None,
                          session_required: bool = True) -> Union[Session, None]:
        pass

    @abstractmethod
    async def refresh_session(self, request: any) -> Session:
        pass

    @abstractmethod
    async def revoke_session(self, session_handle: str) -> bool:
        pass

    @abstractmethod
    async def revoke_all_sessions_for_user(self, user_id: str) -> List[str]:
        pass

    @abstractmethod
    async def get_all_session_handles_for_user(self, user_id: str) -> List[str]:
        pass

    @abstractmethod
    async def revoke_multiple_sessions(self, session_handles: List[str]) -> List[str]:
        pass

    @abstractmethod
    async def get_session_information(self, session_handle: str) -> dict:
        pass

    @abstractmethod
    async def update_session_data(self, session_handle: str, new_session_data: dict) -> None:
        pass

    @abstractmethod
    async def update_access_token_payload(self, session_handle: str, new_access_token_payload: dict) -> None:
        pass

    @abstractmethod
    async def get_access_token_lifetime_ms(self) -> int:
        pass

    @abstractmethod
    async def get_refresh_token_lifetime_ms(self) -> int:
        pass


class SignOutResponse:
    def __init__(self):
        pass

    @abstractmethod
    def to_json(self):
        pass


class SignOutOkayResponse(SignOutResponse):
    def __init__(self):
        self.status = 'OK'
        super().__init__()
        pass

    def to_json(self):
        return {
            'status': self.status
        }


class APIOptions:
    def __init__(self, request: BaseRequest, response: Union[BaseResponse, None],
                 recipe_id: str, config: SessionConfig, recipe_implementation: RecipeInterface,
                 jwt_recipe_implementation: Union[JWTRecipeInterface, None]):
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation
        self.jwt_recipe_implementation = jwt_recipe_implementation


class APIInterface(ABC):
    def __init__(self):
        self.disable_refresh_post = False
        self.disable_signout_post = False

    @abstractmethod
    async def refresh_post(self, api_options: APIOptions):
        pass

    @abstractmethod
    async def signout_post(self, api_options: APIOptions) -> SignOutResponse:
        pass

    @abstractmethod
    async def verify_session(self, api_options: APIOptions, anti_csrf_check: Union[bool, None] = None, session_required: bool = True) -> Union[Session, None]:
        pass
