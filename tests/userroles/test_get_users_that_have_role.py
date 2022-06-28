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
from supertokens_python.querier import Querier
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import userroles
from supertokens_python.utils import is_version_gte
from tests.utils import clean_st, reset, setup_st, start_st
from supertokens_python.recipe.userroles import asyncio
from supertokens_python.recipe.userroles import interfaces


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@mark.asyncio
async def test_get_users_that_have_role():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[userroles.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        return

    users = ["user1", "user2", "user3"]
    role = "role"

    # Create new role:
    result = await asyncio.create_new_role_or_add_permissions(role, [])
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert result.created_new_role

    # Assign the role to users:
    for user in users:
        result = await asyncio.add_role_to_user(user, role)
        assert isinstance(result, interfaces.AddRoleToUserOkResult)
        assert not result.did_user_already_have_role

    # Get all users for a certain role
    result = await asyncio.get_users_that_have_role(role)
    assert isinstance(result, interfaces.GetUsersThatHaveRoleOkResult)
    assert result.users == users


@mark.asyncio
async def test_get_users_for_unknown_role():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[userroles.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        return

    role = "role"

    # Get all users for a certain role
    result = await asyncio.get_users_that_have_role(role)
    assert isinstance(result, interfaces.UnknownRoleError)
