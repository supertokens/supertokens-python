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
from supertokens_python import Supertokens
from typing import Union, List
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal
from supertokens_python.types import UsersResponse


async def get_users_oldest_first(limit: Union[int, None] = None, pagination_token: Union[str, None] = None,
                                 include_recipe_ids: List[str] = None) -> UsersResponse:
    return await Supertokens.get_instance().get_users('ASC', limit, pagination_token, include_recipe_ids)


async def get_users_newest_first(limit: Union[int, None] = None, pagination_token: Union[str, None] = None,
                                 include_recipe_ids: List[str] = None) -> UsersResponse:
    return await Supertokens.get_instance().get_users('DESC', limit, pagination_token, include_recipe_ids)


async def get_user_count(include_recipe_ids: List[str] = None) -> int:
    return await Supertokens.get_instance().get_user_count(include_recipe_ids)
