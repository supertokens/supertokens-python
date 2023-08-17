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
from supertokens_python.recipe import session, userroles, emailpassword, multitenancy
from supertokens_python import init
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
)
from supertokens_python.recipe.emailpassword.asyncio import (
    sign_up,
    sign_in,
    get_user_by_id,
    get_user_by_email,
    create_reset_password_token,
    reset_password_using_token,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    SignUpOkResult,
    SignInOkResult,
    CreateResetPasswordOkResult,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig

from tests.utils import get_st_init_args
from tests.utils import (
    setup_function,
    teardown_function,
    setup_multitenancy_feature,
    start_st,
)


_ = setup_function
_ = teardown_function

pytestmark = mark.asyncio


async def test_multitenancy_in_emailpassword():
    # test that different roles can be assigned for the same user for each tenant
    args = get_st_init_args(
        [
            session.init(),
            userroles.init(),
            emailpassword.init(),
            multitenancy.init(),
        ]
    )
    init(**args)  # type: ignore
    start_st()

    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(email_password_enabled=True))
    await create_or_update_tenant("t2", TenantConfig(email_password_enabled=True))
    await create_or_update_tenant("t3", TenantConfig(email_password_enabled=True))

    user1 = await sign_up("t1", "test@example.com", "password1")
    user2 = await sign_up("t2", "test@example.com", "password2")
    user3 = await sign_up("t3", "test@example.com", "password3")

    assert isinstance(user1, SignUpOkResult)
    assert isinstance(user2, SignUpOkResult)
    assert isinstance(user3, SignUpOkResult)

    assert user1.user.user_id != user2.user.user_id
    assert user2.user.user_id != user3.user.user_id
    assert user3.user.user_id != user1.user.user_id

    assert user1.user.tenant_ids == ["t1"]
    assert user2.user.tenant_ids == ["t2"]
    assert user3.user.tenant_ids == ["t3"]

    # sign in
    ep_user1 = await sign_in("t1", "test@example.com", "password1")
    ep_user2 = await sign_in("t2", "test@example.com", "password2")
    ep_user3 = await sign_in("t3", "test@example.com", "password3")

    assert isinstance(ep_user1, SignInOkResult)
    assert isinstance(ep_user2, SignInOkResult)
    assert isinstance(ep_user3, SignInOkResult)

    assert ep_user1.user.user_id == user1.user.user_id
    assert ep_user2.user.user_id == user2.user.user_id
    assert ep_user3.user.user_id == user3.user.user_id

    # get user by id:
    g_user1 = await get_user_by_id(user1.user.user_id)
    g_user2 = await get_user_by_id(user2.user.user_id)
    g_user3 = await get_user_by_id(user3.user.user_id)

    assert g_user1 == user1.user
    assert g_user2 == user2.user
    assert g_user3 == user3.user

    # get user by email:
    by_email_user1 = await get_user_by_email("t1", "test@example.com")
    by_email_user2 = await get_user_by_email("t2", "test@example.com")
    by_email_user3 = await get_user_by_email("t3", "test@example.com")

    assert by_email_user1 == user1.user
    assert by_email_user2 == user2.user
    assert by_email_user3 == user3.user

    # create password reset token:
    pless_reset_link1 = await create_reset_password_token("t1", user1.user.user_id)
    pless_reset_link2 = await create_reset_password_token("t2", user2.user.user_id)
    pless_reset_link3 = await create_reset_password_token("t3", user3.user.user_id)

    assert isinstance(pless_reset_link1, CreateResetPasswordOkResult)
    assert isinstance(pless_reset_link2, CreateResetPasswordOkResult)
    assert isinstance(pless_reset_link3, CreateResetPasswordOkResult)

    assert pless_reset_link1.token is not None
    assert pless_reset_link2.token is not None
    assert pless_reset_link3.token is not None

    # reset password using token:
    await reset_password_using_token("t1", pless_reset_link1.token, "newpassword1")
    await reset_password_using_token("t2", pless_reset_link2.token, "newpassword2")
    await reset_password_using_token("t3", pless_reset_link3.token, "newpassword3")

    # new password should work:
    s_user1 = await sign_in("t1", "test@example.com", "newpassword1")
    s_user2 = await sign_in("t2", "test@example.com", "newpassword2")
    s_user3 = await sign_in("t3", "test@example.com", "newpassword3")

    assert isinstance(s_user1, SignInOkResult)
    assert isinstance(s_user2, SignInOkResult)
    assert isinstance(s_user3, SignInOkResult)

    assert s_user1.user == user1.user
    assert s_user2.user == user2.user
    assert s_user3.user == user3.user
