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
from supertokens_python import init
from supertokens_python.asyncio import (
    create_user_id_mapping,
)
from supertokens_python.interfaces import (
    CreateUserIdMappingOkResult,
)
from supertokens_python.querier import Querier
from supertokens_python.recipe.emailpassword.interfaces import (
    CreateResetPasswordOkResult,
    SignInOkResult,
    SignUpOkResult,
    UpdateEmailOrPasswordOkResult,
)
from supertokens_python.types import RecipeUserId
from supertokens_python.types.base import AccountInfoInput
from supertokens_python.utils import is_version_gte
from typing_extensions import Literal

from .utils import get_st_config

pytestmark = mark.asyncio

USER_TYPE = Literal["SUPERTOKENS", "EXTERNAL", "ANY"]


async def ep_get_new_user_id(email: str) -> str:
    from supertokens_python.recipe.emailpassword.asyncio import sign_up

    sign_up_res = await sign_up("public", email, "password")
    assert isinstance(sign_up_res, SignUpOkResult)

    return sign_up_res.user.id


async def ep_get_existing_user_id(user_id: str) -> str:
    from supertokens_python.asyncio import get_user

    res = await get_user(user_id)
    assert res is not None
    return res.id


async def ep_get_existing_user_by_email(email: str) -> str:
    from supertokens_python.asyncio import list_users_by_account_info

    res = await list_users_by_account_info("public", AccountInfoInput(email=email))
    assert len(res) == 1
    return res[0].id


async def ep_get_existing_user_by_signin(email: str) -> str:
    from supertokens_python.recipe.emailpassword.asyncio import sign_in

    res = await sign_in("public", email, "password")
    assert isinstance(res, SignInOkResult)
    return res.user.id


async def ep_get_existing_user_after_reset_password(user_id: str) -> str:
    new_password = "password1234"
    from supertokens_python.recipe.emailpassword.asyncio import (
        create_reset_password_token,
        reset_password_using_token,
    )

    result = await create_reset_password_token("public", user_id, "")
    assert isinstance(result, CreateResetPasswordOkResult)
    res = await reset_password_using_token("public", result.token, new_password)
    assert isinstance(res, UpdateEmailOrPasswordOkResult)
    return user_id


async def ep_get_existing_user_after_updating_email_and_sign_in(user_id: str) -> str:
    new_email = "bar@example.com"

    from supertokens_python.recipe.emailpassword.asyncio import (
        sign_in,
        update_email_or_password,
    )

    res = await update_email_or_password(
        RecipeUserId(user_id), new_email, "password1234"
    )
    assert isinstance(res, UpdateEmailOrPasswordOkResult)

    res = await sign_in("public", new_email, "password1234")
    assert isinstance(res, SignInOkResult)
    return res.user.id


@mark.parametrize("use_external_id_info", [(True,), (False,)])
async def test_get_user_id_mapping(use_external_id_info: bool):
    init(**get_st_config())  # type: ignore

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.15"):
        skip()

    email = "test@example.com"

    supertokens_user_id = await ep_get_new_user_id(email)
    external_user_id = "externalId"
    external_id_info = "externalIdInfo" if use_external_id_info else None

    assert await ep_get_existing_user_id(supertokens_user_id) == supertokens_user_id

    # Create user id mapping
    res = await create_user_id_mapping(
        supertokens_user_id, external_user_id, external_id_info
    )
    assert isinstance(res, CreateUserIdMappingOkResult)

    # Now we should get the external user ID instead of ST user ID
    # irrespective of whether we pass ST User ID or External User ID
    assert await ep_get_existing_user_id(supertokens_user_id) == external_user_id
    assert await ep_get_existing_user_id(external_user_id) == external_user_id

    # Same happens for all the functions
    assert await ep_get_existing_user_by_email(email) == external_user_id
    assert await ep_get_existing_user_by_signin(email) == external_user_id
    assert (
        await ep_get_existing_user_after_reset_password(external_user_id)
        == external_user_id
    )
    assert (
        await ep_get_existing_user_after_updating_email_and_sign_in(external_user_id)
        == external_user_id
    )
