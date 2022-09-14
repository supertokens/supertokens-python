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
from supertokens_python.recipe import userroles, session
from supertokens_python.recipe.userroles import asyncio, interfaces
from supertokens_python.utils import is_version_gte
from tests.utils import clean_st, reset, setup_st, start_st


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@mark.asyncio
async def test_create_new_role():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[userroles.init(), session.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        skip()

    role = "role"

    # Create a new role
    result = await asyncio.create_new_role_or_add_permissions(role, [])
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert result.created_new_role


@mark.asyncio
async def test_create_new_role_twice():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[userroles.init(), session.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        skip()

    role = "role"

    # Create a new role
    result = await asyncio.create_new_role_or_add_permissions(role, [])
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert result.created_new_role

    # Create the new role again
    result = await asyncio.create_new_role_or_add_permissions(role, [])
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert not result.created_new_role


@mark.asyncio
async def test_create_new_role_with_permissions():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[userroles.init(), session.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        skip()

    permissions = ["permission1"]
    role = "role"

    # Create a new role
    result = await asyncio.create_new_role_or_add_permissions(role, permissions)
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert result.created_new_role

    # Get permissions for the role
    result = await asyncio.get_permissions_for_role(role)
    assert isinstance(result, interfaces.GetPermissionsForRoleOkResult)
    assert result.permissions == permissions


@mark.asyncio
async def test_add_permissions_to_new_role_():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[userroles.init(), session.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        skip()

    permissions = ["permission1", "permission2", "permission3"]
    role = "role"

    # Create a new role with only one of the permissions
    result = await asyncio.create_new_role_or_add_permissions(role, permissions[0:])
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert result.created_new_role

    # Add remaining permissions to the role
    result = await asyncio.create_new_role_or_add_permissions(role, permissions[1:])
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert not result.created_new_role

    # Get permissions for the role
    result = await asyncio.get_permissions_for_role(role)
    assert isinstance(result, interfaces.GetPermissionsForRoleOkResult)
    assert result.permissions == permissions


@mark.asyncio
async def test_add_duplicate_permission():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[userroles.init(), session.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.14"):
        # If the version less than 2.14, user roles recipe doesn't exist. So skip the test
        skip()

    permissions = ["permission1", "permission2"]
    role = "role"

    # Create a new role
    result = await asyncio.create_new_role_or_add_permissions(role, permissions)
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert result.created_new_role

    # Add duplicate permissions to the role
    result = await asyncio.create_new_role_or_add_permissions(role, permissions)
    assert isinstance(result, interfaces.CreateNewRoleOrAddPermissionsOkResult)
    assert not result.created_new_role

    # Get permissions for the role
    result = await asyncio.get_permissions_for_role(role)
    assert isinstance(result, interfaces.GetPermissionsForRoleOkResult)
    assert result.permissions == permissions
