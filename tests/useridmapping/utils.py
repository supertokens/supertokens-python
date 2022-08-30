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

from supertokens_python import SupertokensConfig, InputAppInfo
from supertokens_python.recipe import emailpassword, session, usermetadata

st_config = {
    "supertokens_config": SupertokensConfig("http://localhost:3567"),
    "app_info": InputAppInfo(
        app_name="SuperTokens Demo",
        api_domain="https://api.supertokens.io",
        website_domain="supertokens.io",
    ),
    "framework": "fastapi",
    "recipe_list": [emailpassword.init(), usermetadata.init(), session.init()],
}
