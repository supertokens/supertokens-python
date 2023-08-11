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
import pytest
from pytest import mark, skip
from supertokens_python import init
from supertokens_python.interfaces import (
    CreateUserIdMappingOkResult,
    GetUserIdMappingOkResult,
    UnknownSupertokensUserIDError,
    UserIdMappingAlreadyExistsError,
)
from supertokens_python.querier import Querier
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.utils import is_version_gte
from tests.useridmapping.utils import st_config
from tests.utils import clean_st, reset, setup_st, start_st
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.asyncio import create_user_id_mapping, get_user_id_mapping
from supertokens_python.recipe.usermetadata.asyncio import update_user_metadata


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


pytestmark = mark.asyncio


async def test_create_user_id_mapping():
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    sign_up_res = await sign_up("public", "test@example.com", "testPass123")
    assert isinstance(sign_up_res, SignUpOkResult)

    supertokens_user_id = sign_up_res.user.user_id
    external_user_id = "externalId"
    external_user_info = "externalIdInfo"

    # Create User ID Mapping:
    create_user_id_mapping_res = await create_user_id_mapping(
        supertokens_user_id, external_user_id, external_user_info
    )
    assert isinstance(create_user_id_mapping_res, CreateUserIdMappingOkResult)

    # Check that User ID Mapping exists:
    get_user_id_mapping_res = await get_user_id_mapping(
        supertokens_user_id, "SUPERTOKENS"
    )
    assert isinstance(get_user_id_mapping_res, GetUserIdMappingOkResult)
    assert get_user_id_mapping_res.supertokens_user_id == supertokens_user_id
    assert get_user_id_mapping_res.external_user_id == external_user_id
    assert get_user_id_mapping_res.external_user_info == external_user_info


async def test_create_user_id_mapping_without_and_with_force():
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    # Create a user:
    sign_up_res = await sign_up("public", "test@example.com", "testPass123")
    assert isinstance(sign_up_res, SignUpOkResult)

    supertokens_user_id = sign_up_res.user.user_id
    external_user_id = "externalId"

    # Add metadata to the user:
    test_metadata = {"role": "admin"}
    await update_user_metadata(supertokens_user_id, test_metadata)

    # Without force:
    with pytest.raises(Exception) as e:
        await create_user_id_mapping(supertokens_user_id, external_user_id)
    assert str(e.value).endswith("UserId is already in use in UserMetadata recipe\n")

    # With force = False:
    with pytest.raises(Exception) as e:
        await create_user_id_mapping(supertokens_user_id, external_user_id, force=False)
    assert str(e.value).endswith("UserId is already in use in UserMetadata recipe\n")

    # With force = True:
    res = await create_user_id_mapping(
        supertokens_user_id, external_user_id, force=True
    )
    assert isinstance(res, CreateUserIdMappingOkResult)

    # Check that User ID Mapping exists:
    get_user_id_mapping_res = await get_user_id_mapping(
        supertokens_user_id, "SUPERTOKENS"
    )
    assert isinstance(get_user_id_mapping_res, GetUserIdMappingOkResult)
    assert get_user_id_mapping_res.supertokens_user_id == supertokens_user_id
    assert get_user_id_mapping_res.external_user_id == external_user_id
    assert get_user_id_mapping_res.external_user_info is None


async def create_user_id_mapping_with_unknown_supertokens_id():
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    # Create User ID Mapping for non-existing ST user:
    create_user_id_mapping_res = await create_user_id_mapping(
        "non_existing_st_user_id", "external_user_id", "external_user_info"
    )
    assert isinstance(create_user_id_mapping_res, UnknownSupertokensUserIDError)


async def create_user_id_mapping_when_mapping_already_exists():
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    sign_up_res = await sign_up("public", "test@example.com", "testPass123")
    assert isinstance(sign_up_res, SignUpOkResult)

    supertokens_user_id = sign_up_res.user.user_id
    external_user_id = "externalId"

    # Create User ID Mapping:
    res = await create_user_id_mapping(supertokens_user_id, external_user_id)
    assert isinstance(res, CreateUserIdMappingOkResult)

    # Try creating a duplicate mapping where both supertokens_user_id and external_user_id
    # already exist
    res = await create_user_id_mapping(supertokens_user_id, external_user_id)
    assert isinstance(res, UserIdMappingAlreadyExistsError)
    assert res.does_super_tokens_user_id_exist is True
    assert res.does_external_user_id_exist is True

    # Try creating a duplicate mapping where supertokens_user_id exists and but external_user_id doesn't (new)
    res = await create_user_id_mapping(supertokens_user_id, "new_external_user_id")
    assert isinstance(res, UserIdMappingAlreadyExistsError)
    assert res.does_super_tokens_user_id_exist is True
    assert res.does_external_user_id_exist is False

    # Try creating a duplicate mapping where external_user_id exists and but supertokens_user_id doesn't (new)
    sign_up_res = await sign_up("public", "foo@bar.com", "baz")
    assert isinstance(sign_up_res, SignUpOkResult)
    new_supertokens_user_id = sign_up_res.user.user_id

    res = await create_user_id_mapping(new_supertokens_user_id, external_user_id)
    assert isinstance(res, UserIdMappingAlreadyExistsError)
    assert res.does_super_tokens_user_id_exist is False
    assert res.does_external_user_id_exist is True
