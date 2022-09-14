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

from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.normalised_url_path import NormalisedURLPath

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

from .interfaces import RecipeInterface, SignInUpOkResult
from .types import ThirdPartyInfo, User


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        params = {"userId": user_id}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user"), params
        )
        if "status" in response and response["status"] == "OK":
            return User(
                response["user"]["id"],
                response["user"]["email"],
                response["user"]["timeJoined"],
                ThirdPartyInfo(
                    response["user"]["thirdParty"]["userId"],
                    response["user"]["thirdParty"]["id"],
                ),
            )
        return None

    async def get_users_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> List[User]:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/users/by-email"), {"email": email}
        )
        users: List[User] = []
        users_list: List[Dict[str, Any]] = (
            response["users"] if "users" in response else []
        )
        for user in users_list:
            users.append(
                User(
                    user["id"],
                    user["email"],
                    user["timeJoined"],
                    ThirdPartyInfo(
                        user["thirdParty"]["userId"], user["thirdParty"]["id"]
                    ),
                )
            )
        return users

    async def get_user_by_thirdparty_info(
        self,
        third_party_id: str,
        third_party_user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[User, None]:
        params = {
            "thirdPartyId": third_party_id,
            "thirdPartyUserId": third_party_user_id,
        }
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user"), params
        )
        if "status" in response and response["status"] == "OK":
            return User(
                response["user"]["id"],
                response["user"]["email"],
                response["user"]["timeJoined"],
                ThirdPartyInfo(
                    response["user"]["thirdParty"]["userId"],
                    response["user"]["thirdParty"]["id"],
                ),
            )
        return None

    async def sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        user_context: Dict[str, Any],
    ) -> SignInUpOkResult:
        data = {
            "thirdPartyId": third_party_id,
            "thirdPartyUserId": third_party_user_id,
            "email": {"id": email},
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/signinup"), data
        )
        return SignInUpOkResult(
            User(
                response["user"]["id"],
                response["user"]["email"],
                response["user"]["timeJoined"],
                ThirdPartyInfo(
                    response["user"]["thirdParty"]["userId"],
                    response["user"]["thirdParty"]["id"],
                ),
            ),
            response["createdNewUser"],
        )
