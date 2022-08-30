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

from typing_extensions import Literal

from pytest import mark, skip
from supertokens_python import init
from supertokens_python.interfaces import (
    CreateUserIdMappingOkResult,
    UnknownMappingError,
    GetUserIdMappingOkResult,
)
from supertokens_python.querier import Querier
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.utils import is_version_gte
from tests.utils import clean_st, reset, setup_st, start_st
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from .utils import st_config
from supertokens_python.asyncio import (
    create_user_id_mapping,
    get_user_id_mapping,
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


@mark.parametrize("use_external_id_info", [True, False])
async def test_get_user_id_mapping(use_external_id_info: bool):
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    sign_up_res = await sign_up("test@example.com", "password")
    assert isinstance(sign_up_res, SignUpOkResult)

    supertokens_user_id = sign_up_res.user.user_id
    external_user_id = "externalId"
    external_id_info = "externalIdInfo" if use_external_id_info else None

    # Create user id mapping
    res = await create_user_id_mapping(
        supertokens_user_id, external_user_id, external_id_info
    )
    assert isinstance(res, CreateUserIdMappingOkResult)

    # Check the user_id_mapping exists with user_type:
    for t in ["SUPERTOKENS", "EXTERNAL"]:
        user_id_to_check = {
            "SUPERTOKENS": supertokens_user_id,
            "EXTERNAL": external_user_id,
        }[t]
        user_type = cast(USER_TYPE, t)
        res = await get_user_id_mapping(user_id_to_check, user_type)
        assert isinstance(res, GetUserIdMappingOkResult)
        assert res.supertokens_user_id == supertokens_user_id
        assert res.external_user_id == external_user_id
        assert res.external_user_info == external_id_info

    # Check the user_id_mapping exists without passing user_type:
    for t in ["SUPERTOKENS", "EXTERNAL"]:
        user_id_to_check = {
            "SUPERTOKENS": supertokens_user_id,
            "EXTERNAL": external_user_id,
        }[t]
        res = await get_user_id_mapping(user_id_to_check)
        assert isinstance(res, GetUserIdMappingOkResult)
        assert res.supertokens_user_id == supertokens_user_id
        assert res.external_user_id == external_user_id
        assert res.external_user_info == external_id_info


async def test_get_unknown__user_id_mapping():
    init(**st_config)  # type: ignore
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    for t in ["SUPERTOKENS", "EXTERNAL", "ANY"]:
        user_type = cast(USER_TYPE, t)
        res = await get_user_id_mapping("non_existing_user_id", user_type)
        assert isinstance(res, UnknownMappingError)
