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

from pytest import mark, skip
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.querier import Querier
from supertokens_python.recipe import session, userroles
from supertokens_python.recipe.userroles import asyncio, interfaces
from supertokens_python.utils import is_version_gte

from tests.utils import get_new_core_app_url


@mark.asyncio
async def test_create_and_assign_new_role_and_delete_it():
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            userroles.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        skip()

    user_id = "userId"
    roles = ["role1", "role2", "role3"]

    # Create new roles and assign them:
    for role in roles:
        result = await asyncio.create_new_role_or_add_permissions(role, [])
        assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
        assert result.created_new_role

        result = await asyncio.add_role_to_user("public", user_id, role)
        assert isinstance(result, interfaces.AddRoleToUserOkResult)
        assert not result.did_user_already_have_role

    # Delete the 2nd role (role2)
    result = await asyncio.delete_role(roles[1])
    assert isinstance(result, interfaces.DeleteRoleOkResult)
    assert result.did_role_exist

    # Check that role[1] (= "role2") doesn't exist any more (and isn't assigned to anyone)
    result = await asyncio.get_all_roles()
    assert isinstance(result, interfaces.GetAllRolesOkResult)
    assert roles[1] not in result.roles

    result = await asyncio.get_roles_for_user("public", user_id)
    assert isinstance(result, interfaces.GetRolesForUserOkResult)
    assert roles[1] not in result.roles


@mark.asyncio
async def test_delete_non_existent_role():
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            userroles.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        skip()

    role = "role"

    result = await asyncio.delete_role(role)
    assert isinstance(result, interfaces.DeleteRoleOkResult)
    assert not result.did_role_exist
