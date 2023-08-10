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
    associate_user_to_tenant,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.userroles.asyncio import (
    create_new_role_or_add_permissions,
    add_role_to_user,
    get_roles_for_user,
)

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


async def test_multitenancy_in_user_roles():
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

    user = await sign_up("public", "test@example.com", "password1")
    assert isinstance(user, SignUpOkResult)
    user_id = user.user.user_id

    await associate_user_to_tenant("t1", user_id)
    await associate_user_to_tenant("t2", user_id)
    await associate_user_to_tenant("t3", user_id)

    await create_new_role_or_add_permissions("role1", [])
    await create_new_role_or_add_permissions("role2", [])
    await create_new_role_or_add_permissions("role3", [])

    await add_role_to_user("t1", user_id, "role1")
    await add_role_to_user("t1", user_id, "role2")
    await add_role_to_user("t2", user_id, "role2")
    await add_role_to_user("t2", user_id, "role3")
    await add_role_to_user("t3", user_id, "role3")
    await add_role_to_user("t3", user_id, "role1")

    roles = await get_roles_for_user("t1", user_id)
    assert roles.roles == ["role1", "role2"]

    roles = await get_roles_for_user("t2", user_id)
    assert roles.roles == ["role2", "role3"]

    roles = await get_roles_for_user("t3", user_id)
    assert roles.roles == ["role1", "role3"]
