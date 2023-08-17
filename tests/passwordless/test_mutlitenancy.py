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
from supertokens_python.recipe import session, multitenancy, passwordless
from supertokens_python import init
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
)
from supertokens_python.recipe.passwordless.asyncio import (
    create_code,
    consume_code,
    get_user_by_id,
    get_user_by_email,
    ConsumeCodeOkResult,
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


async def test_multitenancy_functions():
    # test that different roles can be assigned for the same user for each tenant
    args = get_st_init_args(
        [
            session.init(),
            passwordless.init(
                contact_config=passwordless.ContactEmailOnlyConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            ),
            multitenancy.init(),
        ]
    )
    init(**args)
    start_st()
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(passwordless_enabled=True))
    await create_or_update_tenant("t2", TenantConfig(passwordless_enabled=True))
    await create_or_update_tenant("t3", TenantConfig(passwordless_enabled=True))

    code1 = await create_code(
        tenant_id="t1", email="test@example.com", user_input_code="123456"
    )
    code2 = await create_code(
        tenant_id="t2", email="test@example.com", user_input_code="456789"
    )
    code3 = await create_code(
        tenant_id="t3", email="test@example.com", user_input_code="789123"
    )

    user1 = await consume_code(
        tenant_id="t1",
        pre_auth_session_id=code1.pre_auth_session_id,
        user_input_code="123456",
        device_id=code1.device_id,
    )
    user2 = await consume_code(
        tenant_id="t2",
        pre_auth_session_id=code2.pre_auth_session_id,
        user_input_code="456789",
        device_id=code2.device_id,
    )
    user3 = await consume_code(
        tenant_id="t3",
        pre_auth_session_id=code3.pre_auth_session_id,
        user_input_code="789123",
        device_id=code3.device_id,
    )

    assert isinstance(user1, ConsumeCodeOkResult)
    assert isinstance(user2, ConsumeCodeOkResult)
    assert isinstance(user3, ConsumeCodeOkResult)

    assert user1.user.user_id != user2.user.user_id
    assert user2.user.user_id != user3.user.user_id
    assert user3.user.user_id != user1.user.user_id

    assert user1.user.tenant_ids == ["t1"]
    assert user2.user.tenant_ids == ["t2"]
    assert user3.user.tenant_ids == ["t3"]

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
