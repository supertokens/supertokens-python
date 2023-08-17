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
from abc import ABC, abstractmethod
from typing import Any, Awaitable, Dict, List, TypeVar, Union

_T = TypeVar("_T")


class ThirdPartyInfo:
    def __init__(self, third_party_user_id: str, third_party_id: str):
        self.user_id = third_party_user_id
        self.id = third_party_id


class User:
    def __init__(
        self,
        recipe_id: str,
        user_id: str,
        time_joined: int,
        email: Union[str, None],
        phone_number: Union[str, None],
        third_party_info: Union[ThirdPartyInfo, None],
        tenant_ids: List[str],
    ):
        self.recipe_id = recipe_id
        self.user_id = user_id
        self.email = email
        self.time_joined = time_joined
        self.third_party_info = third_party_info
        self.phone_number = phone_number
        self.tenant_ids = tenant_ids

    def to_json(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "recipeId": self.recipe_id,
            "user": {
                "id": self.user_id,
                "timeJoined": self.time_joined,
                "tenantIds": self.tenant_ids,
            },
        }

        if self.email is not None:
            res["user"]["email"] = self.email
        if self.phone_number is not None:
            res["user"]["phoneNumber"] = self.phone_number
        if self.third_party_info is not None:
            res["user"]["thirdParty"] = self.third_party_info.__dict__

        return res


class UsersResponse:
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]):
        self.users: List[User] = users
        self.next_pagination_token: Union[str, None] = next_pagination_token


class APIResponse(ABC):
    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        pass


class GeneralErrorResponse(APIResponse):
    def __init__(self, message: str):
        self.status = "GENERAL_ERROR"
        self.message = message

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "message": self.message}


MaybeAwaitable = Union[Awaitable[_T], _T]
