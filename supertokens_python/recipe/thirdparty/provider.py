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
import abc
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from .types import UserInfo, AccessTokenAPI, AuthorisationRedirectAPI


class Provider(abc.ABC):
    def __init__(self, provider_id: str, client_id: str, is_default: bool):
        self.id = provider_id
        self.client_id = client_id
        self.is_default = is_default
        self.redirect_uri = None

    @abc.abstractmethod
    async def get_profile_info(self, auth_code_response: any) -> UserInfo:
        pass

    @abc.abstractmethod
    def get_authorisation_redirect_api_info(self) -> AuthorisationRedirectAPI:
        pass

    @abc.abstractmethod
    def get_access_token_api_info(
            self, redirect_uri: str, auth_code_from_request: str) -> AccessTokenAPI:
        pass

    def get_redirect_uri(self) -> Union[None, str]:
        return self.redirect_uri
