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
from supertokens_python.recipe import session, multitenancy, thirdparty
from supertokens_python import init
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    create_or_update_third_party_config,
)
from supertokens_python.recipe.thirdparty.asyncio import (
    manually_create_or_update_user,
    get_user_by_id,
    get_users_by_email,
    get_user_by_third_party_info,
    get_provider,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig

from tests.utils import get_st_init_args
from tests.utils import setup_function, teardown_function, setup_multitenancy_feature


_ = setup_function
_ = teardown_function

pytestmark = mark.asyncio


async def test_multitenancy_functions():
    # test that different roles can be assigned for the same user for each tenant
    args = get_st_init_args([session.init(), thirdparty.init(), multitenancy.init()])
    init(**args)  # type: ignore
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(third_party_enabled=True))
    await create_or_update_tenant("t2", TenantConfig(third_party_enabled=True))
    await create_or_update_tenant("t3", TenantConfig(third_party_enabled=True))

    # sign up:
    user1a = await manually_create_or_update_user(
        "google", "googleid1", "test@example.com", "t1"
    )
    user1b = await manually_create_or_update_user(
        "facebook", "fbid1", "test@example.com", "t1"
    )
    user2a = await manually_create_or_update_user(
        "google", "googleid1", "test@example.com", "t2"
    )
    user2b = await manually_create_or_update_user(
        "facebook", "fbid1", "test@example.com", "t2"
    )
    user3a = await manually_create_or_update_user(
        "google", "googleid1", "test@example.com", "t3"
    )
    user3b = await manually_create_or_update_user(
        "facebook", "fbid1", "test@example.com", "t3"
    )

    assert user1a.user.tenant_ids == ["t1"]
    assert user1b.user.tenant_ids == ["t1"]
    assert user2a.user.tenant_ids == ["t2"]
    assert user2b.user.tenant_ids == ["t2"]
    assert user3a.user.tenant_ids == ["t3"]
    assert user3b.user.tenant_ids == ["t3"]

    # get user by id:
    g_user1a = await get_user_by_id(user1a.user.user_id)
    g_user1b = await get_user_by_id(user1b.user.user_id)
    g_user2a = await get_user_by_id(user2a.user.user_id)
    g_user2b = await get_user_by_id(user2b.user.user_id)
    g_user3a = await get_user_by_id(user3a.user.user_id)
    g_user3b = await get_user_by_id(user3b.user.user_id)

    assert g_user1a == user1a.user
    assert g_user1b == user1b.user
    assert g_user2a == user2a.user
    assert g_user2b == user2b.user
    assert g_user3a == user3a.user
    assert g_user3b == user3b.user

    # get user by email:
    by_email_user1 = await get_users_by_email("test@example.com", "t1")
    by_email_user2 = await get_users_by_email("test@example.com", "t2")
    by_email_user3 = await get_users_by_email("test@example.com", "t3")

    assert by_email_user1 == [user1a.user, user1b.user]
    assert by_email_user2 == [user2a.user, user2b.user]
    assert by_email_user3 == [user3a.user, user3b.user]

    # get user by thirdparty id:
    g_user_by_tpid1a = await get_user_by_third_party_info("google", "googleid1", "t1")
    g_user_by_tpid1b = await get_user_by_third_party_info("facebook", "fbid1", "t1")
    g_user_by_tpid2a = await get_user_by_third_party_info("google", "googleid1", "t2")
    g_user_by_tpid2b = await get_user_by_third_party_info("facebook", "fbid1", "t2")
    g_user_by_tpid3a = await get_user_by_third_party_info("google", "googleid1", "t3")
    g_user_by_tpid3b = await get_user_by_third_party_info("facebook", "fbid1", "t3")

    assert g_user_by_tpid1a == user1a.user
    assert g_user_by_tpid1b == user1b.user
    assert g_user_by_tpid2a == user2a.user
    assert g_user_by_tpid2b == user2b.user
    assert g_user_by_tpid3a == user3a.user
    assert g_user_by_tpid3b == user3b.user


async def test_get_provider():
    args = get_st_init_args([session.init(), thirdparty.init(), multitenancy.init()])
    init(**args)
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(third_party_enabled=True))
    await create_or_update_tenant("t1", TenantConfig(third_party_enabled=True))
    await create_or_update_tenant("t1", TenantConfig(third_party_enabled=True))

    await create_or_update_third_party_config(
        "t1",
        thirdparty.ProviderConfig(
            "google", clients=[thirdparty.ProviderClientConfig("a")]
        ),
    )
    await create_or_update_third_party_config(
        "t1",
        thirdparty.ProviderConfig(
            "facebook", clients=[thirdparty.ProviderClientConfig("a")]
        ),
    )

    await create_or_update_third_party_config(
        "t2",
        thirdparty.ProviderConfig(
            "facebook", clients=[thirdparty.ProviderClientConfig("a")]
        ),
    )
    await create_or_update_third_party_config(
        "t2",
        thirdparty.ProviderConfig(
            "discord", clients=[thirdparty.ProviderClientConfig("a")]
        ),
    )

    await create_or_update_third_party_config(
        "t3",
        thirdparty.ProviderConfig(
            "discord", clients=[thirdparty.ProviderClientConfig("a")]
        ),
    )
    await create_or_update_third_party_config(
        "t3",
        thirdparty.ProviderConfig(
            "linkedin", clients=[thirdparty.ProviderClientConfig("a")]
        ),
    )

    provider1 = await get_provider("google", None, "t1")
    assert provider1.provider.config.thirdparty_id == "google"

    provider2 = await get_provider("facebook", None, "t1")
    assert provider2.provider.config.thirdparty_id == "facebook"

    provider3 = await get_provider("facebook", None, "t2")
    assert provider3.provider.config.thirdparty_id == "facebook"

    provider4 = await get_provider("discord", None, "t2")
    assert provider4.provider.config.thirdparty_id == "discord"

    provider5 = await get_provider("discord", None, "t3")
    assert provider5.provider.config.thirdparty_id == "discord"

    provider6 = await get_provider("linkedin", None, "t3")
    assert provider6.provider.config.thirdparty_id == "linkedin"
