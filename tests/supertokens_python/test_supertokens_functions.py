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

from typing import List

from pytest import mark
from tests.utils import clean_st, reset, setup_st, start_st

from supertokens_python import InputAppInfo, SupertokensConfig
from supertokens_python import asyncio as st_asyncio
from supertokens_python import init
from supertokens_python.querier import Querier
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword import asyncio as ep_asyncio
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.utils import is_version_gte


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@mark.asyncio
async def test_supertokens_functions():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    emails = [f"{u}@example.com" for u in ["foo", "bar", "baz"]]
    user_ids: List[str] = []
    for e in emails:
        signup_resp = await ep_asyncio.sign_up("public", e, "secret_pass")
        assert isinstance(signup_resp, SignUpOkResult)
        user_ids.append(signup_resp.user.user_id)

    # Get user count
    assert await st_asyncio.get_user_count() == len(emails)

    # Get users in ascending order by joining time
    users_asc = (await st_asyncio.get_users_oldest_first("public", limit=10)).users
    emails_asc = [user.email for user in users_asc]
    assert emails_asc == emails

    # Get users in descending order by joining time
    users_desc = (await st_asyncio.get_users_newest_first("public", limit=10)).users
    emails_desc = [user.email for user in users_desc]
    assert emails_desc == emails[::-1]

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.10"):
        # If the version is less than 2.10, delete user feature doesn't exist, so mark the test successful
        return

    # Delete the 2nd user (bar@example.com)
    await st_asyncio.delete_user(user_ids[1])

    # Again, get users in ascending order by joining time
    # We expect that the 2nd user (bar@example.com) must be absent.
    users_asc = (await st_asyncio.get_users_oldest_first("public", limit=10)).users
    emails_asc = [user.email for user in users_asc]
    assert emails[1] not in emails_asc  # The 2nd user must be deleted now.

    if not is_version_gte(version, "2.20"):
        # If the version is less than 2.20, query users doesn't exist, so we mark the test successful
        return
    users_asc = (
        await st_asyncio.get_users_oldest_first(
            "public", limit=10, query={"email": "baz"}
        )
    ).users
    users_desc = (
        await st_asyncio.get_users_newest_first(
            "public", limit=10, query={"email": "baz"}
        )
    ).users
    emails_asc = [user.email for user in users_asc]
    emails_desc = [user.email for user in users_desc]
    assert len(emails_asc) == 1
    assert len(emails_desc) == 1

    users_asc = (
        await st_asyncio.get_users_oldest_first(
            "public", limit=10, query={"email": "john"}
        )
    ).users
    users_desc = (
        await st_asyncio.get_users_newest_first(
            "public", limit=10, query={"email": "john"}
        )
    ).users
    emails_asc = [user.email for user in users_asc]
    emails_desc = [user.email for user in users_desc]
    assert len(emails_asc) == 0
    assert len(emails_desc) == 0
