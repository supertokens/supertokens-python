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

from pytest import mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.asyncio import get_users_newest_first, get_users_oldest_first
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.asyncio import sign_up

from tests.utils import get_new_core_app_url


@mark.asyncio
async def test_get_users_pagination():
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init(anti_csrf="VIA_TOKEN"), emailpassword.init()],
    )

    for i in range(5):
        await sign_up("public", f"dummy{i}@gmail.com", "validpass123")

    # Get all the users (No limit)
    response = await get_users_newest_first("public")
    assert [user.emails[0] for user in response.users] == [
        f"dummy{i}@gmail.com" for i in range(5)
    ][::-1]

    # Get only the oldest user
    response = await get_users_oldest_first("public", limit=1)
    assert [user.emails[0] for user in response.users] == ["dummy0@gmail.com"]

    # Test pagination
    response = await get_users_oldest_first(
        "public", limit=1, pagination_token=response.next_pagination_token
    )
    assert [user.emails[0] for user in response.users] == ["dummy1@gmail.com"]
