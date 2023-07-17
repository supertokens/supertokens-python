# Copyright (c) 2023, VRAI Labs and/or its affiliates. All rights reserved.
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
from fastapi import FastAPI
from pytest import mark, fixture
from starlette.testclient import TestClient

from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, multitenancy, session
from tests.utils import (
    setup_function,
    teardown_function,
    get_st_init_args,
    start_st,
    setup_multitenancy_feature,
)

_ = setup_function
_ = teardown_function

pytestmark = mark.asyncio

from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    list_all_tenants,
    get_tenant,
    delete_tenant,
    create_or_update_third_party_config,
    delete_third_party_config,
    associate_user_to_tenant,
    dissociate_user_from_tenant,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_up, get_user_by_id
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.thirdparty.provider import (
    ProviderConfig,
    ProviderClientConfig,
)


@fixture(scope="function")
async def client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def test_tenant_crud():
    args = get_st_init_args([multitenancy.init()])
    init(**args)
    start_st()
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(email_password_enabled=True))
    await create_or_update_tenant("t2", TenantConfig(passwordless_enabled=True))
    await create_or_update_tenant("t3", TenantConfig(third_party_enabled=True))

    tenants = await list_all_tenants()
    assert len(tenants.tenants) == 4

    t1_config = await get_tenant("t1")
    assert t1_config.emailpassword.enabled is True
    assert t1_config.passwordless.enabled is False
    assert t1_config.third_party.enabled is False
    assert t1_config.core_config == {}

    t2_config = await get_tenant("t2")
    assert t2_config.emailpassword.enabled is False
    assert t2_config.passwordless.enabled is True
    assert t2_config.third_party.enabled is False
    assert t2_config.core_config == {}

    t3_config = await get_tenant("t3")
    assert t3_config.emailpassword.enabled is False
    assert t3_config.passwordless.enabled is False
    assert t3_config.third_party.enabled is True
    assert t3_config.core_config == {}

    # update tenant1 to add passwordless:
    await create_or_update_tenant("t1", TenantConfig(passwordless_enabled=True))
    t1_config = await get_tenant("t1")
    assert t1_config.emailpassword.enabled is True
    assert t1_config.passwordless.enabled is True
    assert t1_config.third_party.enabled is False
    assert t1_config.core_config == {}

    # update tenant1 to add thirdparty:
    await create_or_update_tenant("t1", TenantConfig(third_party_enabled=True))
    t1_config = await get_tenant("t1")
    assert t1_config.emailpassword.enabled is True
    assert t1_config.passwordless.enabled is True
    assert t1_config.third_party.enabled is True
    assert t1_config.core_config == {}

    # delete tenant2:
    await delete_tenant("t2")
    tenants = await list_all_tenants()
    assert len(tenants.tenants) == 3


async def test_tenant_thirdparty_config():
    args = get_st_init_args([multitenancy.init()])
    init(**args)
    start_st()
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(email_password_enabled=True))
    await create_or_update_third_party_config(
        "t1",
        config=ProviderConfig(
            third_party_id="google",
            name="Google",
            clients=[ProviderClientConfig(client_id="abcd")],
        ),
    )

    tenant_config = await get_tenant("t1")

    assert len(tenant_config.third_party.providers) == 1
    assert tenant_config.third_party.providers[0].third_party_id == "google"
    assert tenant_config.third_party.providers[0].clients is not None
    assert len(tenant_config.third_party.providers[0].clients) == 1
    assert tenant_config.third_party.providers[0].clients[0].client_id == "abcd"

    # update thirdparty config
    await create_or_update_third_party_config(
        "t1",
        ProviderConfig(
            third_party_id="google",
            name="Custom name",
            clients=[ProviderClientConfig(client_id="efgh")],
        ),
    )

    tenant_config = await get_tenant("t1")
    assert len(tenant_config.third_party.providers) == 1
    assert tenant_config.third_party.providers[0].third_party_id == "google"
    assert tenant_config.third_party.providers[0].name == "Custom name"
    assert tenant_config.third_party.providers[0].clients is not None
    assert len(tenant_config.third_party.providers[0].clients) == 1
    assert tenant_config.third_party.providers[0].clients[0].client_id == "efgh"

    # delete thirdparty config
    await delete_third_party_config("t1", "google")

    tenant_config = await get_tenant("t1")
    assert len(tenant_config.third_party.providers) == 0


async def test_user_association_and_disassociation_with_tenants():
    args = get_st_init_args([session.init(), emailpassword.init(), multitenancy.init()])
    init(**args)
    start_st()
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(email_password_enabled=True))
    await create_or_update_tenant("t2", TenantConfig(passwordless_enabled=True))
    await create_or_update_tenant("t3", TenantConfig(third_party_enabled=True))

    signup_response = await sign_up("test@example.com", "password1")
    assert isinstance(signup_response, SignUpOkResult)
    user_id = signup_response.user.user_id

    await associate_user_to_tenant("t1", user_id)
    await associate_user_to_tenant("t2", user_id)
    await associate_user_to_tenant("t3", user_id)

    user = await get_user_by_id(user_id)
    assert user is not None
    assert len(user.tenant_ids) == 4  # public + 3 tenants

    await dissociate_user_from_tenant("t1", user_id)
    await dissociate_user_from_tenant("t2", user_id)
    await dissociate_user_from_tenant("t3", user_id)

    user = await get_user_by_id(user_id)
    assert user is not None
    assert len(user.tenant_ids) == 1  # public only
