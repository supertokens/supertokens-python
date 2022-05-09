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

import pytest
from supertokens_python import InputAppInfo, Supertokens, SupertokensConfig, init
from supertokens_python.recipe import session
import asyncio


@pytest.mark.asyncio
async def test_asgi_telemetry():
    with pytest.warns(None) as record:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            mode='asgi',
            recipe_list=[session.init(
                anti_csrf='VIA_TOKEN',
                cookie_domain='supertokens.io',
                override=session.InputOverrideConfig()
            )],
            telemetry=True
        )
        await asyncio.sleep(1)

    for warn in record:
        if warn.category is RuntimeWarning:
            assert False, 'Asyncio error'

    assert Supertokens.get_instance()._telemetry_status == 'SKIPPED'  # type: ignore pylint: disable=W0212


def test_wsgi_telemetry():
    with pytest.warns(None) as record:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='flask',
            mode='wsgi',
            recipe_list=[session.init(
                anti_csrf='VIA_TOKEN',
                cookie_domain='supertokens.io',
                override=session.InputOverrideConfig()
            )],
            telemetry=True
        )

    for warn in record:
        if warn.category is RuntimeWarning:
            assert False, 'Asyncio error'

    assert Supertokens.get_instance()._telemetry_status == 'SKIPPED'  # type: ignore pylint: disable=W0212
