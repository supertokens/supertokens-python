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
from fastapi import FastAPI
from pytest import mark, fixture

from supertokens_python.framework.fastapi import get_middleware
from fastapi.testclient import TestClient
from supertokens_python.recipe import session, thirdpartypasswordless
from supertokens_python import init
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_third_party_config,
)
from supertokens_python.recipe.thirdparty.provider import (
    ProviderConfig,
    ProviderClientConfig,
)

from tests.utils import get_st_init_args
from tests.utils import (
    setup_function,
    teardown_function,
    start_st,
)


_ = setup_function
_ = teardown_function

pytestmark = mark.asyncio


@fixture(scope="function")
async def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def test_calling_authorisation_url_api_with_empty_init(app: TestClient):
    args = get_st_init_args(
        [
            session.init(
                get_token_transfer_method=lambda _, __, ___: "cookie",
                anti_csrf="VIA_TOKEN",
            ),
            thirdpartypasswordless.init(
                contact_config=thirdpartypasswordless.ContactEmailOnlyConfig(),
                flow_type="MAGIC_LINK",
            ),
        ]
    )
    init(**args)  # type: ignore
    start_st()

    res = app.get(
        "/auth/authorisationurl?thirdPartyId=google&redirectURIOnProviderDashboard=redirect"
    )
    assert res.status_code == 400
    assert res.json() == {
        "message": "the provider google could not be found in the configuration"
    }


async def test_calling_authorisation_url_api_with_empty_init_with_dynamic_thirdparty_provider(
    app: TestClient,
):
    args = get_st_init_args(
        [
            session.init(
                get_token_transfer_method=lambda _, __, ___: "cookie",
                anti_csrf="VIA_TOKEN",
            ),
            thirdpartypasswordless.init(
                contact_config=thirdpartypasswordless.ContactEmailOnlyConfig(),
                flow_type="MAGIC_LINK",
            ),
        ]
    )
    init(**args)  # type: ignore
    start_st()

    await create_or_update_third_party_config(
        "public",
        ProviderConfig(
            third_party_id="google",
            name="Google",
            clients=[
                ProviderClientConfig(
                    client_id="google-client-id",
                    client_secret="google-client-secret",
                )
            ],
        ),
    )

    res = app.get(
        "/auth/authorisationurl?thirdPartyId=google&redirectURIOnProviderDashboard=redirect"
    )
    body = res.json()
    assert body["status"] == "OK"
    assert (
        body["urlWithQueryParams"]
        == "https://accounts.google.com/o/oauth2/v2/auth?client_id=google-client-id&redirect_uri=redirect&response_type=code&scope=openid+email&included_grant_scopes=true&access_type=offline"
    )
