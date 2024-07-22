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
from phonenumbers import format_number, parse  # type: ignore
import phonenumbers  # type: ignore

_T = TypeVar("_T")


class RecipeUserId:
    def __init__(self, recipe_user_id: str):
        self.recipe_user_id = recipe_user_id

    def get_as_string(self) -> str:
        return self.recipe_user_id


class ThirdPartyInfo:
    def __init__(self, third_party_id: str, third_party_user_id: str):
        self.id = third_party_id
        self.user_id = third_party_user_id


class LoginMethod:
    def __init__(
        self,
        recipe_id: str,
        recipe_user_id: str,
        tenant_ids: List[str],
        email: Union[str, None],
        phone_number: Union[str, None],
        third_party: Union[ThirdPartyInfo, None],
        time_joined: int,
        verified: bool,
    ):
        self.recipe_id = recipe_id
        self.recipe_user_id = RecipeUserId(recipe_user_id)
        self.tenant_ids = tenant_ids
        self.email = email
        self.phone_number = phone_number
        self.third_party = third_party
        self.time_joined = time_joined
        self.verified = verified

    def has_same_email_as(self, email: Union[str, None]) -> bool:
        if email is None:
            return False
        return (
            self.email is not None
            and self.email.lower().strip() == email.lower().strip()
        )

    def has_same_phone_number_as(self, phone_number: Union[str, None]) -> bool:
        if phone_number is None:
            return False

        cleaned_phone = phone_number.strip()
        try:
            cleaned_phone = format_number(
                parse(phone_number, None), phonenumbers.PhoneNumberFormat.E164
            )
        except Exception:
            pass  # here we just use the stripped version

        return self.phone_number is not None and self.phone_number == cleaned_phone

    def has_same_third_party_info_as(
        self, third_party: Union[ThirdPartyInfo, None]
    ) -> bool:
        if third_party is None or self.third_party is None:
            return False
        return (
            self.third_party.id.strip() == third_party.id.strip()
            and self.third_party.user_id.strip() == third_party.user_id.strip()
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "recipeId": self.recipe_id,
            "recipeUserId": self.recipe_user_id.get_as_string(),
            "tenantIds": self.tenant_ids,
            "email": self.email,
            "phoneNumber": self.phone_number,
            "thirdParty": self.third_party.__dict__ if self.third_party else None,
            "timeJoined": self.time_joined,
            "verified": self.verified,
        }


class AccountLinkingUser:
    def __init__(
        self,
        user_id: str,
        is_primary_user: bool,
        tenant_ids: List[str],
        emails: List[str],
        phone_numbers: List[str],
        third_party: List[ThirdPartyInfo],
        login_methods: List[LoginMethod],
        time_joined: int,
    ):
        self.id = user_id
        self.is_primary_user = is_primary_user
        self.tenant_ids = tenant_ids
        self.emails = emails
        self.phone_numbers = phone_numbers
        self.third_party = third_party
        self.login_methods = login_methods
        self.time_joined = time_joined

    def to_json(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "isPrimaryUser": self.is_primary_user,
            "tenantIds": self.tenant_ids,
            "emails": self.emails,
            "phoneNumbers": self.phone_numbers,
            "thirdParty": self.third_party,
            "loginMethods": [lm.to_json() for lm in self.login_methods],
            "timeJoined": self.time_joined,
        }


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
    def __init__(
        self, users: List[AccountLinkingUser], next_pagination_token: Union[str, None]
    ):
        self.users: List[AccountLinkingUser] = users
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
