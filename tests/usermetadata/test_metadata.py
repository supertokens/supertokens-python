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

from typing import Any, Dict

from pytest import mark, skip
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.querier import Querier
from supertokens_python.recipe import usermetadata
from supertokens_python.recipe.usermetadata.asyncio import (
    clear_user_metadata,
    get_user_metadata,
    update_user_metadata,
)
from supertokens_python.recipe.usermetadata.interfaces import (
    ClearUserMetadataResult,
    RecipeInterface,
)
from supertokens_python.recipe.usermetadata.utils import InputOverrideConfig
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
async def test_that_usermetadata_recipe_works_as_expected():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[usermetadata.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.13"):
        # If the version less than 2.13, user metadata doesn't exist. So skip the test
        skip()

    TEST_USER_ID = "userId"
    TEST_METADATA: Dict[str, Any] = {
        "role": "ädmin äÆ \uFDFD",  # Ensures that utf8 metadata is supported by the SDK
        "name": {"first": "John", "last": "Doe"},
    }

    get_metadata_res = await get_user_metadata(TEST_USER_ID)
    assert get_metadata_res.metadata == {}

    update_metadata_res = await update_user_metadata(TEST_USER_ID, TEST_METADATA)
    assert update_metadata_res.metadata == TEST_METADATA

    get_metadata_res = await get_user_metadata(TEST_USER_ID)
    assert get_metadata_res.metadata == TEST_METADATA

    # Overriding updates with shallow merge:
    # Passing {'role': None, ...} should remove 'role' from the metdata
    TEST_METADATA["role"] = None
    # 'first' is inside 'role' so it won't get
    # removed despite setting 'first' as None
    TEST_METADATA["name"]["first"] = None
    update_metadata_res = await update_user_metadata(TEST_USER_ID, TEST_METADATA)
    TEST_METADATA.pop("role")
    assert update_metadata_res.metadata == TEST_METADATA

    get_metadata_res = await get_user_metadata(TEST_USER_ID)
    assert get_metadata_res.metadata == TEST_METADATA

    clear_metadata_res = await clear_user_metadata(TEST_USER_ID)
    assert isinstance(clear_metadata_res, ClearUserMetadataResult)

    get_metadata_res = await get_user_metadata(TEST_USER_ID)
    assert get_metadata_res.metadata == {}


@mark.asyncio
async def test_usermetadata_recipe_shallow_merge():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[usermetadata.init()],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.13"):
        # If the version less than 2.13, user metadata doesn't exist. So skip the test
        skip()

    TEST_USER_ID = "userId"

    TEST_METADATA_ORIGINAL: Dict[str, Any] = {
        "updated": {
            "subObjectNull": "this will become null",
            "subObjectCleared": "this will be removed",
            "subObjectUpdate": "this will become a number",
        },
        "cleared": "this should not be in the end result",
    }

    TEST_METADATA_UPDATE: Dict[str, Any] = {
        "updated": {
            "subObjectNull": None,
            "subObjectUpdate": 123,
            "subObjectNewProp": "this will appear",
        },
        "cleared": None,
        "newRootProp": "this should appear in the end result",
    }

    TEST_METADATA_RESULT: Dict[str, Any] = {
        "updated": {
            "subObjectNull": None,
            "subObjectUpdate": 123,
            "subObjectNewProp": "this will appear",
        },
        "newRootProp": "this should appear in the end result",
    }

    get_metadata_res = await get_user_metadata(TEST_USER_ID)
    assert get_metadata_res.metadata == {}

    update_metadata_res = await update_user_metadata(
        TEST_USER_ID, TEST_METADATA_ORIGINAL
    )
    assert update_metadata_res.metadata == TEST_METADATA_ORIGINAL

    update_metadata_res = await update_user_metadata(TEST_USER_ID, TEST_METADATA_UPDATE)
    assert update_metadata_res.metadata == TEST_METADATA_RESULT


@mark.asyncio
async def test_recipe_override():
    override_used = False

    def override_func(oi: RecipeInterface) -> RecipeInterface:
        oi_get_user_metadata = oi.get_user_metadata

        async def new_get_user_metadata(user_id: str, user_context: Dict[str, Any]):
            nonlocal override_used
            override_used = True
            return await oi_get_user_metadata(user_id, user_context)

        oi.get_user_metadata = new_get_user_metadata
        return oi

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            usermetadata.init(override=InputOverrideConfig(functions=override_func))
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.13"):
        # If the version less than 2.13, user metadata doesn't exist. So skip the test
        skip()

    res = await get_user_metadata("userId")
    assert res.metadata == {}

    assert override_used is True
