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

from supertokens_python.recipe.emailpassword.interfaces import APIInterface
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import \
    APIInterface as ThirdPartyEmailPasswordAPIInterface


def get_interface_impl(
        api_implementation: ThirdPartyEmailPasswordAPIInterface) -> APIInterface:
    implementation = APIInterface()

    if api_implementation.disable_email_exists_get:
        implementation.disable_email_exists_get = True
    if api_implementation.disable_generate_password_reset_token_post:
        implementation.disable_generate_password_reset_token_post = True
    if api_implementation.disable_password_reset_post:
        implementation.disable_password_reset_post = True
    if api_implementation.disable_emailpassword_sign_in_post:
        implementation.disable_sign_in_post = True
    if api_implementation.disable_emailpassword_sign_up_post:
        implementation.disable_sign_up_post = True

    implementation.email_exists_get = api_implementation.email_exists_get
    implementation.generate_password_reset_token_post = api_implementation.generate_password_reset_token_post
    implementation.password_reset_post = api_implementation.password_reset_post
    implementation.sign_up_post = api_implementation.emailpassword_sign_up_post
    implementation.sign_in_post = api_implementation.emailpassword_sign_in_post

    return implementation
