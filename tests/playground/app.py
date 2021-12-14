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

from supertokens_python import init, InputAppInfo, SupertokensConfig
from supertokens_python.recipe import emailpassword
# from supertokens_python.recipe.emailpassword import InputFormField
# from supertokens_python.recipe.emailverification import InputOverrideConfig as EVInputOverrideConfig
# from supertokens_python.recipe.session.utils import OverrideConfig

init(
    app_info=InputAppInfo(
        app_name='',
        website_domain='',
        api_domain=''
    ),
    supertokens_config=SupertokensConfig(
        connection_uri='',
        api_key=''
    ),
    framework='fastapi',
    recipe_list=[
        emailpassword.init()
    ]
)
