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
from __future__ import annotations

from supertokens_python.recipe.thirdparty.interfaces import APIInterface

from ..interfaces import APIInterface as ThirdPartyPasswordlessAPIInterface


def get_interface_impl(
        api_implementation: ThirdPartyPasswordlessAPIInterface) -> APIInterface:
    implementation = APIInterface()

    implementation.disable_authorisation_url_get = api_implementation.disable_authorisation_url_get
    implementation.disable_sign_in_up_post = api_implementation.disable_thirdparty_sign_in_up_post
    implementation.disable_apple_redirect_handler_post = api_implementation.disable_apple_redirect_handler_post

    if not implementation.disable_sign_in_up_post:
        implementation.sign_in_up_post = api_implementation.thirdparty_sign_in_up_post

    implementation.authorisation_url_get = api_implementation.authorisation_url_get
    implementation.apple_redirect_handler_post = api_implementation.apple_redirect_handler_post

    return implementation
