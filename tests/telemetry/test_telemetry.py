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

import asyncio
import os

import pytest

from supertokens_python import InputAppInfo, Supertokens, SupertokensConfig, init
from supertokens_python.recipe import session
from tests.utils import reset


@pytest.mark.asyncio
async def test_telemetry():
    reset()
    with pytest.warns(None) as _:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            mode="asgi",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    override=session.InputOverrideConfig(),
                )
            ],
            telemetry=True,
        )
        await asyncio.sleep(1)

        assert Supertokens.get_instance().telemetry is not None

        assert Supertokens.get_instance().telemetry


@pytest.mark.asyncio
async def test_read_from_env():
    reset()
    os.environ["TEST_MODE"] = "testing"
    with pytest.warns(None) as _:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            mode="asgi",
            recipe_list=[
                session.init(
                    anti_csrf="VIA_TOKEN",
                    cookie_domain="supertokens.io",
                    override=session.InputOverrideConfig(),
                )
            ],
        )
        await asyncio.sleep(1)

        assert not Supertokens.get_instance().telemetry
