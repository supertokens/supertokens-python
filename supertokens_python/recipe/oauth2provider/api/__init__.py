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

from .auth import auth_get as auth_get
from .end_session import end_session_get as end_session_get
from .end_session import end_session_post as end_session_post
from .introspect_token import introspect_token_post as introspect_token_post
from .login import login as login
from .login_info import login_info_get as login_info_get
from .logout import logout_post as logout_post
from .revoke_token import revoke_token_post as revoke_token_post
from .token import token_post as token_post
from .user_info import user_info_get as user_info_get
