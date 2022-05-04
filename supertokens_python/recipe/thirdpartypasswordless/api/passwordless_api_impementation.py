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

from supertokens_python.recipe.passwordless.interfaces import APIInterface

from ..interfaces import APIInterface as ThirdPartyPasswordlessAPIInterface


def get_interface_impl(
        api_implementation: ThirdPartyPasswordlessAPIInterface) -> APIInterface:
    implementation = APIInterface()

    implementation.disable_email_exists_get = api_implementation.disable_passwordless_user_email_exists_get
    implementation.disable_resend_code_post = api_implementation.disable_resend_code_post
    implementation.disable_create_code_post = api_implementation.disable_create_code_post
    implementation.disable_consume_code_post = api_implementation.disable_consume_code_post
    implementation.disable_phone_number_exists_get = api_implementation.disable_passwordless_user_phone_number_exists_get

    implementation.email_exists_get = api_implementation.passwordless_user_email_exists_get
    implementation.consume_code_post = api_implementation.consume_code_post
    implementation.create_code_post = api_implementation.create_code_post
    implementation.phone_number_exists_get = api_implementation.passwordless_user_phone_number_exists_get
    implementation.resend_code_post = api_implementation.resend_code_post

    return implementation
