# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import Union

from supertokens_python import AppInfo

from .types import OverrideConfig, TOTPConfig, TOTPNormalisedConfig


def validate_and_normalise_user_input(
    app_info: AppInfo, config: Union[TOTPConfig, None]
) -> TOTPNormalisedConfig:
    if config is None:
        config = TOTPConfig()

    issuer = config.issuer if config.issuer is not None else app_info.app_name
    default_skew = config.default_skew if config.default_skew is not None else 1
    default_period = config.default_period if config.default_period is not None else 30

    if config.override is None:
        override = OverrideConfig()
    else:
        override = OverrideConfig(
            functions=config.override.functions,
            apis=config.override.apis,
        )

    return TOTPNormalisedConfig(
        issuer=issuer,
        default_skew=default_skew,
        default_period=default_period,
        override=override,
    )
