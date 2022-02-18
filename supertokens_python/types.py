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
from typing import List, Union


class ThirdPartyInfo:
    def __init__(self, third_party_user_id: str, third_party_id: str):
        self.user_id = third_party_user_id
        self.id = third_party_id


class User:
    def __init__(self, recipe_id: str, user_id: str, time_joined: int, email: Union[str, None], phone_number: Union[str, None], third_party_info: Union[ThirdPartyInfo, None]):
        self.recipe_id = recipe_id
        self.user_id = user_id
        self.email = email
        self.time_joined = time_joined
        self.third_party_info = third_party_info
        self.phone_number = phone_number


class UsersResponse:
    def __init__(self, users: List[User],
                 next_pagination_token: Union[str, None]):
        self.users: List[User] = users
        self.next_pagination_token: Union[str, None] = next_pagination_token
