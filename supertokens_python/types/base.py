"""
Types in `supertokens_python.types` as of 0.29
"""

# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import TYPE_CHECKING, Any, Awaitable, Dict, List, Optional, TypeVar, Union

import phonenumbers  # type: ignore
from phonenumbers import format_number, parse  # type: ignore
from typing_extensions import Literal, TypeAlias

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
    from supertokens_python.recipe.webauthn.types.base import (
        WebauthnInfo,
        WebauthnInfoInput,
    )


# Generics
_T = TypeVar("_T")
MaybeAwaitable = Union[Awaitable[_T], _T]

# Common Types
UserContext: TypeAlias = Dict[str, Any]


class RecipeUserId:
    def __init__(self, recipe_user_id: str):
        self.recipe_user_id = recipe_user_id

    def get_as_string(self) -> str:
        return self.recipe_user_id

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, RecipeUserId):
            return self.recipe_user_id == other.recipe_user_id
        return False


class AccountInfo:
    def __init__(
        self,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        third_party: Optional[ThirdPartyInfo] = None,
        webauthn: Optional[WebauthnInfo] = None,
    ):
        self.email = email
        self.phone_number = phone_number
        self.third_party = third_party
        self.webauthn = webauthn

    def to_json(self) -> Dict[str, Any]:
        json_repo: Dict[str, Any] = {}
        if self.email is not None:
            json_repo["email"] = self.email
        if self.phone_number is not None:
            json_repo["phoneNumber"] = self.phone_number
        if self.third_party is not None:
            json_repo["thirdParty"] = {
                "id": self.third_party.id,
                "userId": self.third_party.user_id,
            }
        if self.webauthn is not None:
            json_repo["webauthn"] = {
                "credentialIds": self.webauthn.credential_ids,
            }
        return json_repo


class AccountInfoInput:
    def __init__(
        self,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        third_party: Optional[ThirdPartyInfo] = None,
        webauthn: Optional[WebauthnInfoInput] = None,
    ):
        self.email = email
        self.phone_number = phone_number
        self.third_party = third_party
        self.webauthn = webauthn

    def to_json(self) -> Dict[str, Any]:
        json_repo: Dict[str, Any] = {}
        if self.email is not None:
            json_repo["email"] = self.email
        if self.phone_number is not None:
            json_repo["phoneNumber"] = self.phone_number
        if self.third_party is not None:
            json_repo["thirdParty"] = {
                "id": self.third_party.id,
                "userId": self.third_party.user_id,
            }
        if self.webauthn is not None:
            json_repo["webauthn"] = {
                "credentialId": self.webauthn.credential_id,
            }
        return json_repo


class LoginMethod(AccountInfo):
    def __init__(
        self,
        recipe_id: Literal["emailpassword", "thirdparty", "passwordless", "webauthn"],
        recipe_user_id: str,
        tenant_ids: List[str],
        email: Union[str, None],
        phone_number: Union[str, None],
        third_party: Union[ThirdPartyInfo, None],
        webauthn: Optional[WebauthnInfo],
        time_joined: int,
        verified: bool,
    ):
        super().__init__(email, phone_number, third_party, webauthn=webauthn)
        self.recipe_id: Literal[
            "emailpassword", "thirdparty", "passwordless", "webauthn"
        ] = recipe_id
        self.recipe_user_id = RecipeUserId(recipe_user_id)
        self.tenant_ids: List[str] = tenant_ids
        self.time_joined = time_joined
        self.verified = verified

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, LoginMethod):
            return (
                self.recipe_id == other.recipe_id
                and self.recipe_user_id == other.recipe_user_id
                and self.tenant_ids == other.tenant_ids
                and self.email == other.email
                and self.phone_number == other.phone_number
                and self.third_party == other.third_party
                and self.time_joined == other.time_joined
                and self.verified == other.verified
            )
        return False

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
        if third_party is None:
            return False
        return (
            self.third_party is not None
            and self.third_party.id.strip() == third_party.id.strip()
            and self.third_party.user_id.strip() == third_party.user_id.strip()
        )

    def has_same_webauthn_info_as(self, webauthn: Optional[WebauthnInfoInput]) -> bool:
        if webauthn is None:
            return False

        return (
            self.webauthn is not None
            and webauthn.credential_id in self.webauthn.credential_ids
        )

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "recipeId": self.recipe_id,
            "recipeUserId": self.recipe_user_id.get_as_string(),
            "tenantIds": self.tenant_ids,
            "timeJoined": self.time_joined,
            "verified": self.verified,
        }
        if self.email is not None:
            result["email"] = self.email
        if self.phone_number is not None:
            result["phoneNumber"] = self.phone_number
        if self.third_party is not None:
            result["thirdParty"] = self.third_party.to_json()
        if self.webauthn is not None:
            result["webauthn"] = self.webauthn.to_json()
        return result

    @staticmethod
    def from_json(json: Dict[str, Any]) -> "LoginMethod":
        from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo as TPI
        from supertokens_python.recipe.webauthn.types.base import WebauthnInfo

        return LoginMethod(
            recipe_id=json["recipeId"],
            recipe_user_id=json["recipeUserId"],
            tenant_ids=json["tenantIds"],
            email=(
                json["email"] if "email" in json and json["email"] is not None else None
            ),
            phone_number=(
                json["phoneNumber"]
                if "phoneNumber" in json and json["phoneNumber"] is not None
                else None
            ),
            third_party=(
                TPI(json["thirdParty"]["userId"], json["thirdParty"]["id"])
                if "thirdParty" in json and json["thirdParty"] is not None
                else None
            ),
            webauthn=(
                WebauthnInfo(credential_ids=json["webauthn"]["credentialIds"])
                if "webauthn" in json and json["webauthn"] is not None
                else None
            ),
            time_joined=json["timeJoined"],
            verified=json["verified"],
        )


class User:
    def __init__(
        self,
        user_id: str,
        is_primary_user: bool,
        tenant_ids: List[str],
        emails: List[str],
        phone_numbers: List[str],
        third_party: List[ThirdPartyInfo],
        webauthn: WebauthnInfo,
        login_methods: List[LoginMethod],
        time_joined: int,
    ):
        self.id = user_id
        self.is_primary_user = is_primary_user
        self.tenant_ids = tenant_ids
        self.emails = emails
        self.phone_numbers = phone_numbers
        self.third_party = third_party
        self.webauthn = webauthn
        self.login_methods = login_methods
        self.time_joined = time_joined

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, User):
            return (
                self.id == other.id
                and self.is_primary_user == other.is_primary_user
                and self.tenant_ids == other.tenant_ids
                and self.emails == other.emails
                and self.phone_numbers == other.phone_numbers
                and self.third_party == other.third_party
                and self.webauthn == other.webauthn
                and self.login_methods == other.login_methods
                and self.time_joined == other.time_joined
            )
        return False

    def to_json(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "isPrimaryUser": self.is_primary_user,
            "tenantIds": self.tenant_ids,
            "emails": self.emails,
            "phoneNumbers": self.phone_numbers,
            "thirdParty": [tp.to_json() for tp in self.third_party],
            "webauthn": self.webauthn.to_json(),
            "loginMethods": [lm.to_json() for lm in self.login_methods],
            "timeJoined": self.time_joined,
        }

    @staticmethod
    def from_json(json: Dict[str, Any]) -> "User":
        from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo as TPI
        from supertokens_python.recipe.webauthn.types.base import WebauthnInfo

        if "webauthn" in json:
            webauthn = WebauthnInfo.from_json(json["webauthn"])
        else:
            webauthn = WebauthnInfo(credential_ids=[])

        return User(
            user_id=json["id"],
            is_primary_user=json["isPrimaryUser"],
            tenant_ids=json["tenantIds"],
            emails=json["emails"],
            phone_numbers=json["phoneNumbers"],
            third_party=[TPI.from_json(tp) for tp in json["thirdParty"]],
            webauthn=webauthn,
            login_methods=[LoginMethod.from_json(lm) for lm in json["loginMethods"]],
            time_joined=json["timeJoined"],
        )
