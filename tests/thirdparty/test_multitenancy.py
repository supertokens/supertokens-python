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
from supertokens_python import init
from supertokens_python.asyncio import get_user, list_users_by_account_info
from supertokens_python.recipe import multitenancy, session, thirdparty
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    create_or_update_third_party_config,
)
from supertokens_python.recipe.multitenancy.interfaces import (
    TenantConfigCreateOrUpdate,
)
from supertokens_python.recipe.thirdparty.asyncio import (
    get_provider,
    manually_create_or_update_user,
)
from supertokens_python.recipe.thirdparty.interfaces import (
    ManuallyCreateOrUpdateUserOkResult,
)
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types.base import AccountInfoInput

from tests.utils import (
    get_new_core_app_url,
    get_st_init_args,
)

pytestmark = mark.asyncio


async def test_thirtyparty_multitenancy_functions():
    # test that different roles can be assigned for the same user for each tenant
    args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[session.init(), thirdparty.init(), multitenancy.init()],
    )
    init(**args)

    await create_or_update_tenant(
        "t1", TenantConfigCreateOrUpdate(first_factors=["thirdparty"])
    )
    await create_or_update_tenant(
        "t2", TenantConfigCreateOrUpdate(first_factors=["thirdparty"])
    )
    await create_or_update_tenant(
        "t3", TenantConfigCreateOrUpdate(first_factors=["thirdparty"])
    )

    # sign up:
    user1a = await manually_create_or_update_user(
        "t1", "google", "googleid1", "test@example.com", True, None
    )
    assert isinstance(user1a, ManuallyCreateOrUpdateUserOkResult)
    user1b = await manually_create_or_update_user(
        "t1", "facebook", "fbid1", "test@example.com", True, None
    )
    assert isinstance(user1b, ManuallyCreateOrUpdateUserOkResult)
    user2a = await manually_create_or_update_user(
        "t2", "google", "googleid1", "test@example.com", True, None
    )
    assert isinstance(user2a, ManuallyCreateOrUpdateUserOkResult)
    user2b = await manually_create_or_update_user(
        "t2", "facebook", "fbid1", "test@example.com", True, None
    )
    assert isinstance(user2b, ManuallyCreateOrUpdateUserOkResult)
    user3a = await manually_create_or_update_user(
        "t3", "google", "googleid1", "test@example.com", True, None
    )
    assert isinstance(user3a, ManuallyCreateOrUpdateUserOkResult)
    user3b = await manually_create_or_update_user(
        "t3", "facebook", "fbid1", "test@example.com", True, None
    )
    assert isinstance(user3b, ManuallyCreateOrUpdateUserOkResult)

    assert user1a.user.tenant_ids == ["t1"]
    assert user1b.user.tenant_ids == ["t1"]
    assert user2a.user.tenant_ids == ["t2"]
    assert user2b.user.tenant_ids == ["t2"]
    assert user3a.user.tenant_ids == ["t3"]
    assert user3b.user.tenant_ids == ["t3"]

    # get user by id:
    g_user1a = await get_user(user1a.user.id)
    g_user1b = await get_user(user1b.user.id)
    g_user2a = await get_user(user2a.user.id)
    g_user2b = await get_user(user2b.user.id)
    g_user3a = await get_user(user3a.user.id)
    g_user3b = await get_user(user3b.user.id)

    assert g_user1a == user1a.user
    assert g_user1b == user1b.user
    assert g_user2a == user2a.user
    assert g_user2b == user2b.user
    assert g_user3a == user3a.user
    assert g_user3b == user3b.user

    # get user by email:
    by_email_user1 = await list_users_by_account_info(
        "t1", AccountInfoInput(email="test@example.com")
    )
    by_email_user2 = await list_users_by_account_info(
        "t2", AccountInfoInput(email="test@example.com")
    )
    by_email_user3 = await list_users_by_account_info(
        "t3", AccountInfoInput(email="test@example.com")
    )

    assert by_email_user1 == [user1a.user, user1b.user]
    assert by_email_user2 == [user2a.user, user2b.user]
    assert by_email_user3 == [user3a.user, user3b.user]

    # get user by thirdparty id:
    g_user_by_tpid1a = await list_users_by_account_info(
        "t1",
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_id="google", third_party_user_id="googleid1"
            )
        ),
    )
    g_user_by_tpid1b = await list_users_by_account_info(
        "t1",
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_id="facebook", third_party_user_id="fbid1"
            )
        ),
    )
    g_user_by_tpid2a = await list_users_by_account_info(
        "t2",
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_id="google", third_party_user_id="googleid1"
            )
        ),
    )
    g_user_by_tpid2b = await list_users_by_account_info(
        "t2",
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_id="facebook", third_party_user_id="fbid1"
            )
        ),
    )
    g_user_by_tpid3a = await list_users_by_account_info(
        "t3",
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_id="google", third_party_user_id="googleid1"
            )
        ),
    )
    g_user_by_tpid3b = await list_users_by_account_info(
        "t3",
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_id="facebook", third_party_user_id="fbid1"
            )
        ),
    )

    assert g_user_by_tpid1a == [user1a.user]
    assert g_user_by_tpid1b == [user1b.user]
    assert g_user_by_tpid2a == [user2a.user]
    assert g_user_by_tpid2b == [user2b.user]
    assert g_user_by_tpid3a == [user3a.user]
    assert g_user_by_tpid3b == [user3b.user]


async def test_get_provider():
    args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[
                        thirdparty.ProviderInput(
                            thirdparty.ProviderConfig(
                                third_party_id="google",
                            )
                        ),
                        thirdparty.ProviderInput(
                            thirdparty.ProviderConfig(
                                third_party_id="facebook",
                            )
                        ),
                        thirdparty.ProviderInput(
                            thirdparty.ProviderConfig(
                                third_party_id="discord",
                            )
                        ),
                        thirdparty.ProviderInput(
                            thirdparty.ProviderConfig(
                                third_party_id="linkedin",
                            )
                        ),
                    ]
                )
            ),
            multitenancy.init(),
        ],
    )
    init(**args)

    await create_or_update_tenant(
        "t1", TenantConfigCreateOrUpdate(first_factors=["thirdparty"])
    )
    await create_or_update_tenant(
        "t2", TenantConfigCreateOrUpdate(first_factors=["thirdparty"])
    )
    await create_or_update_tenant(
        "t3", TenantConfigCreateOrUpdate(first_factors=["thirdparty"])
    )

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

    provider1 = await get_provider("t1", "google", None)
    assert provider1 is not None
    assert provider1.config.third_party_id == "google"

    provider2 = await get_provider("t1", "facebook", None)
    assert provider2 is not None
    assert provider2.config.third_party_id == "facebook"

    provider3 = await get_provider("t2", "facebook", None)
    assert provider3 is not None
    assert provider3.config.third_party_id == "facebook"

    provider4 = await get_provider("t2", "discord", None)
    assert provider4 is not None
    assert provider4.config.third_party_id == "discord"

    provider5 = await get_provider("t3", "discord", None)
    assert provider5 is not None
    assert provider5.config.third_party_id == "discord"

    provider6 = await get_provider("t3", "linkedin", None)
    assert provider6 is not None
    assert provider6.config.third_party_id == "linkedin"


async def test_get_provider_returns_correct_config_from_core():
    args = get_st_init_args(url=get_new_core_app_url(), recipe_list=[thirdparty.init()])
    init(**args)

    await create_or_update_third_party_config(
        "public",
        thirdparty.ProviderConfig(
            "google",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id="core-client-id",
                    client_secret="core-secret",
                )
            ],
        ),
    )

    thirdparty_info = await get_provider("public", "google")
    assert thirdparty_info is not None
    assert thirdparty_info.config.third_party_id == "google"

    client = thirdparty_info.config
    assert client.client_id == "core-client-id"
    assert client.client_secret == "core-secret"
    assert thirdparty_info.config.user_info_map is not None
    from_id_token_payload = thirdparty_info.config.user_info_map.from_id_token_payload
    assert from_id_token_payload is not None

    assert from_id_token_payload.user_id == "sub"
    assert from_id_token_payload.email == "email"
    assert from_id_token_payload.email_verified == "email_verified"

    from_user_info_api = thirdparty_info.config.user_info_map.from_user_info_api
    assert from_user_info_api is not None
    assert from_user_info_api.user_id == "sub"
    assert from_user_info_api.email == "email"
    assert from_user_info_api.email_verified == "email_verified"
