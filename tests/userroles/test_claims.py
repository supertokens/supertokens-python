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
from unittest.mock import MagicMock
from typing import List

import pytest
from pytest import mark
from supertokens_python import init
from supertokens_python.recipe import userroles, session
from supertokens_python.recipe.session.exceptions import ClaimValidationError
from tests.utils import (
    start_st,
    setup_function,
    teardown_function,
    get_st_init_args,
    min_api_version,
)
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.recipe.userroles import (
    UserRoleClaim,
    PermissionClaim,
)
from supertokens_python.recipe.userroles.asyncio import (
    create_new_role_or_add_permissions,
    add_role_to_user,
)

_ = setup_function  # type: ignore
_ = teardown_function  # type: ignore

pytestmark = mark.asyncio


@min_api_version("2.14")
async def test_add_claims_to_session_without_config():
    st_args = get_st_init_args([userroles.init(), session.init()])
    init(**st_args)
    start_st()

    user_id = "userId"
    req = MagicMock()

    s = await create_new_session(req, user_id)
    assert s.sync_get_claim_value(UserRoleClaim) == []
    assert (await s.get_claim_value(PermissionClaim)) == []


@min_api_version("2.14")
async def test_claims_not_added_to_session_if_disabled():
    st_args = get_st_init_args(
        [
            userroles.init(
                skip_adding_roles_to_access_token=True,
                skip_adding_permissions_to_access_token=True,
            ),
            session.init(),
        ]
    )
    init(**st_args)
    start_st()

    user_id = "userId"
    req = MagicMock()

    s = await create_new_session(req, user_id)
    assert (await s.get_claim_value(UserRoleClaim)) is None
    assert s.sync_get_claim_value(PermissionClaim) is None


@min_api_version("2.14")
async def test_add_claims_to_session_with_values():
    st_args = get_st_init_args([userroles.init(), session.init()])
    init(**st_args)
    start_st()

    user_id = "userId"
    role = "role"
    req = MagicMock()

    await create_new_role_or_add_permissions(role, ["a", "b"])
    await add_role_to_user(user_id, role)

    s = await create_new_session(req, user_id)
    assert s.sync_get_claim_value(UserRoleClaim) == [role]
    value: List[str] = await s.get_claim_value(PermissionClaim)  # type: ignore
    assert sorted(value) == sorted(["a", "b"])


@min_api_version("2.14")
async def test_should_validate_roles():
    st_args = get_st_init_args([userroles.init(), session.init()])
    init(**st_args)
    start_st()

    user_id = "userId"
    role = "role"
    invalid_role = "invalid_role"
    req = MagicMock()

    await create_new_role_or_add_permissions(role, ["a", "b"])
    await add_role_to_user(user_id, role)

    s = await create_new_session(req, user_id)

    await s.assert_claims([UserRoleClaim.validators.includes(role)])
    with pytest.raises(Exception) as e:
        await s.assert_claims([UserRoleClaim.validators.includes(invalid_role)])
    assert e.typename == "InvalidClaimsError"
    err: ClaimValidationError
    (err,) = e.value.payload  # type: ignore
    assert err.id == UserRoleClaim.key
    assert err.reason == {
        "message": "wrong value",
        "expectedToInclude": invalid_role,
        "actualValue": [role],
    }


@min_api_version("2.14")
async def test_should_validate_roles_after_refetch():
    st_args = get_st_init_args(
        [
            userroles.init(
                skip_adding_roles_to_access_token=True,
            ),
            session.init(),
        ]
    )
    init(**st_args)
    start_st()

    user_id = "userId"
    role = "role"
    req = MagicMock()

    s = await create_new_session(req, user_id)

    await create_new_role_or_add_permissions(role, ["a", "b"])
    await add_role_to_user(user_id, role)

    await s.assert_claims([UserRoleClaim.validators.includes(role)])


@min_api_version("2.14")
async def test_should_validate_permissions():
    st_args = get_st_init_args([userroles.init(), session.init()])
    init(**st_args)
    start_st()

    user_id = "userId"
    role = "role"
    permissions = ["a", "b"]
    invalid_permission = "invalid_permission"
    req = MagicMock()

    await create_new_role_or_add_permissions(role, permissions)
    await add_role_to_user(user_id, role)

    s = await create_new_session(req, user_id)

    await s.assert_claims([PermissionClaim.validators.includes("a")])
    with pytest.raises(Exception) as e:
        await s.assert_claims([PermissionClaim.validators.includes(invalid_permission)])
    assert e.typename == "InvalidClaimsError"
    err: ClaimValidationError
    (err,) = e.value.payload  # type: ignore
    assert err.id == PermissionClaim.key
    assert err.reason is not None
    actual_value = err.reason.pop("actualValue")
    assert sorted(actual_value) == sorted(permissions)
    assert err.reason == {
        "message": "wrong value",
        "expectedToInclude": invalid_permission,
    }


@min_api_version("2.14")
async def test_should_validate_permissions_after_refetch():
    st_args = get_st_init_args(
        [
            userroles.init(
                skip_adding_permissions_to_access_token=True,
            ),
            session.init(),
        ]
    )
    init(**st_args)
    start_st()

    user_id = "userId"
    role = "role"
    permissions = ["a", "b"]
    req = MagicMock()

    s = await create_new_session(req, user_id)

    await create_new_role_or_add_permissions(role, permissions)
    await add_role_to_user(user_id, role)

    await s.assert_claims([PermissionClaim.validators.includes("a")])
