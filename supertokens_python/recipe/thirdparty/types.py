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

from typing import Any, Callable, Dict, Union, Optional, TYPE_CHECKING

from supertokens_python.framework.request import BaseRequest

if TYPE_CHECKING:
    from supertokens_python.types import AccountLinkingUser


class ThirdPartyInfo:
    def __init__(self, third_party_user_id: str, third_party_id: str):
        self.user_id = third_party_user_id
        self.id = third_party_id

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, self.__class__)
            and self.user_id == other.user_id
            and self.id == other.id
        )


class RawUserInfoFromProvider:
    def __init__(
        self,
        from_id_token_payload: Optional[Dict[str, Any]],
        from_user_info_api: Optional[Dict[str, Any]],
    ):
        self.from_id_token_payload = from_id_token_payload
        self.from_user_info_api = from_user_info_api


class UserInfoEmail:
    def __init__(self, email: str, is_verified: bool):
        self.id: str = email
        self.is_verified: bool = is_verified


class UserInfo:
    def __init__(
        self,
        third_party_user_id: str,
        email: Union[UserInfoEmail, None] = None,
        raw_user_info_from_provider: Optional[RawUserInfoFromProvider] = None,
    ):
        self.third_party_user_id: str = third_party_user_id
        self.email: Union[UserInfoEmail, None] = email
        self.raw_user_info_from_provider = (
            raw_user_info_from_provider or RawUserInfoFromProvider({}, {})
        )


class AccessTokenAPI:
    def __init__(self, url: str, params: Dict[str, str]):
        self.url = url
        self.params = params


class AuthorisationRedirectAPI:
    def __init__(
        self, url: str, params: Dict[str, Union[Callable[[BaseRequest], str], str]]
    ):
        self.url = url
        self.params = params


class SignInUpResponse:
    def __init__(self, user: AccountLinkingUser, is_new_user: bool):
        self.user = user
        self.is_new_user = is_new_user


class ThirdPartyIngredients:
    pass
