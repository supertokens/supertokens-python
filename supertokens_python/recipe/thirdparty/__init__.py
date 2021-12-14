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
from typing import Union

from .utils import SignInAndUpFeature, InputOverrideConfig

from .recipe import ThirdPartyRecipe
from . import exceptions
from .providers import (
    Google,
    Github,
    Apple,
    Facebook,
    Discord,
    GoogleWorkspaces
)
from ..emailverification.utils import InputEmailVerificationConfig


def init(sign_in_and_up_feature: SignInAndUpFeature,
         email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
         override: Union[InputOverrideConfig, None] = None):
    return ThirdPartyRecipe.init(sign_in_and_up_feature, email_verification_feature, override)
