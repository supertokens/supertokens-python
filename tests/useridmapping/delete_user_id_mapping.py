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
from typing import cast

import pytest
from typing_extensions import Literal

from pytest import mark, skip
from supertokens_python import init
from supertokens_python.interfaces import (
    DeleteUserIdMappingOkResult,
    CreateUserIdMappingOkResult,
    UnknownMappingError,
)
from supertokens_python.querier import Querier
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.usermetadata.asyncio import update_user_metadata
from supertokens_python.utils import is_version_gte
from tests.utils import clean_st, reset, setup_st, start_st
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from .utils import st_config
from supertokens_python.asyncio import (
    create_user_id_mapping,
    get_user_id_mapping,
    delete_user_id_mapping,
)


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


pytestmark = mark.asyncio

USER_TYPE = Literal["SUPERTOKENS", "EXTERNAL", "ANY"]


@mark.parametrize("user_type", ["SUPERTOKENS", "EXTERNAL", "ANY"])
async def test_delete_user_id_mapping(user_type: USER_TYPE):
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    # Create ST User
    sign_up_res = await sign_up("test@example.com", "password")
    assert isinstance(sign_up_res, SignUpOkResult)

    supertokens_user_id = sign_up_res.user.user_id
    external_user_id = "externalId"
    external_id_info = "externalIdInfo"

    # Create user id mapping
    res = await create_user_id_mapping(
        supertokens_user_id, external_user_id, external_id_info
    )
    assert isinstance(res, CreateUserIdMappingOkResult)

    user_id_to_delete = {
        "SUPERTOKENS": supertokens_user_id,
        "EXTERNAL": external_user_id,
        "ANY": external_user_id,
    }[user_type]

    # Delete the mapping
    res = await delete_user_id_mapping(user_id_to_delete, user_type)
    assert isinstance(res, DeleteUserIdMappingOkResult)
    assert res.did_mapping_exist is True

    # Ensure that the mapping is deleted
    res = await get_user_id_mapping(user_id_to_delete, user_type)
    assert isinstance(res, UnknownMappingError)


async def test_delete_user_id_mapping_without_and_with_force():
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    # Create a user:
    sign_up_res = await sign_up("test@example.com", "testPass123")
    assert isinstance(sign_up_res, SignUpOkResult)

    supertokens_user_id = sign_up_res.user.user_id
    external_user_id = "externalId"
    external_user_info = "externalIdInfo"

    res = await create_user_id_mapping(
        supertokens_user_id, external_user_id, external_user_info
    )
    assert isinstance(res, CreateUserIdMappingOkResult)

    # Add metadata to the user:
    test_metadata = {"role": "admin"}
    await update_user_metadata(external_user_id, test_metadata)

    # Without force:
    with pytest.raises(Exception) as e:
        await delete_user_id_mapping(external_user_id, "EXTERNAL")
    assert str(e.value).endswith("UserId is already in use in UserMetadata recipe\n")

    # With force = False:
    with pytest.raises(Exception) as e:
        await delete_user_id_mapping(external_user_id, "EXTERNAL", force=False)
    assert str(e.value).endswith("UserId is already in use in UserMetadata recipe\n")

    # With force = True:
    res = await delete_user_id_mapping(external_user_id, "EXTERNAL", force=True)
    assert isinstance(res, DeleteUserIdMappingOkResult)
    assert res.did_mapping_exist is True

    # Check that User ID Mapping doesn't exist:
    get_user_id_mapping_res = await get_user_id_mapping(
        supertokens_user_id, "SUPERTOKENS"
    )
    assert isinstance(get_user_id_mapping_res, UnknownMappingError)


async def test_delete_unknown_user_id_mapping():
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    for t in ["SUPERTOKENS", "EXTERNAL", "ANY"]:
        user_type = cast(USER_TYPE, t)
        res = await delete_user_id_mapping("non_existing_user_id", user_type)
        assert isinstance(res, DeleteUserIdMappingOkResult)
        assert res.did_mapping_exist is False
