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

from __future__ import annotations

from supertokens_python.recipe.thirdparty.provider import Provider
from .custom import GenericProvider, NewProvider
from ..provider import Provider, ProviderInput


class BitbucketImpl(GenericProvider):
    pass


def Bitbucket(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if input.config.name is None:
        input.config.name = "Bitbucket"

    if input.config.authorization_endpoint is None:
        input.config.authorization_endpoint = (
            "https://bitbucket.org/site/oauth2/authorize"
        )

    if input.config.token_endpoint is None:
        input.config.token_endpoint = "https://bitbucket.org/site/oauth2/access_token"

    if input.config.user_info_endpoint is None:
        input.config.user_info_endpoint = "https://api.bitbucket.org/2.0/user"

    return NewProvider(input, BitbucketImpl)
