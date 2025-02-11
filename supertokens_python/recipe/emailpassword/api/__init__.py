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
from .email_exists import handle_email_exists_api as handle_email_exists_api
from .generate_password_reset_token import (
    handle_generate_password_reset_token_api as handle_generate_password_reset_token_api,
)
from .password_reset import handle_password_reset_api as handle_password_reset_api
from .signin import handle_sign_in_api as handle_sign_in_api
from .signup import handle_sign_up_api as handle_sign_up_api
