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
from supertokens_python.querier import Querier
from supertokens_python.recipe import usermetadata
from supertokens_python.recipe.usermetadata.recipe import UserMetadataRecipe
from supertokens_python.utils import compare_version
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
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name='SuperTokens Demo',
            api_domain='https://api.supertokens.io',
            website_domain='supertokens.io'
        ),
        framework='fastapi',
        recipe_list=[usermetadata.init()]
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if compare_version(version, '2.13.0') != '2.13.0':
        # If the version less than 2.13.0, user metadata doesn't exist. So skip the test
        return

    TEST_USER_ID = "userId"
    TEST_METADATA = {"role": "admin", "name": {"first": "John", "last": "Doe"}}

    s: UserMetadataRecipe = UserMetadataRecipe.get_instance()

    res_get_metadata = await s.recipe_implementation.get_user_metadata(TEST_USER_ID)
    assert res_get_metadata == {'metadata': {}, 'status': 'OK'}

    res_update_metadata = await s.recipe_implementation.update_user_metadata(TEST_USER_ID, TEST_METADATA)
    assert res_update_metadata == {'metadata': TEST_METADATA, 'status': 'OK'}

    res_get_metadata = await s.recipe_implementation.get_user_metadata(TEST_USER_ID)
    assert res_get_metadata == {'metadata': TEST_METADATA, 'status': 'OK'}

    res_get_metadata = await s.recipe_implementation.clear_user_metadata(TEST_USER_ID)
    assert res_get_metadata == {'status': 'OK'}

    res_get_metadata = await s.recipe_implementation.get_user_metadata(TEST_USER_ID)
    assert res_get_metadata == {'metadata': {}, 'status': 'OK'}
