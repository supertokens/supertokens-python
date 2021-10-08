"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from supertokens_python.recipe.jwt.interfaces import OverrideConfig, JWTConfig
from supertokens_python.supertokens import AppInfo


def validate_and_normalise_user_input(app_info: AppInfo, config):
    override_functions = config['override']['functions'] if 'override' in config and 'functions' in config[
        'override'] else None
    override_apis = config['override']['apis'] if 'override' in config and 'apis' in config[
        'override'] else None

    override_config = OverrideConfig(override_functions, override_apis)

    if "jwtValiditySeconds" not in config:
        return JWTConfig(override_config, 3153600000)
    else:
        return JWTConfig(override_config, config.get("jwtValiditySeconds"))
