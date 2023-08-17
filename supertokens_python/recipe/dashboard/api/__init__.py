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
from .analytics import handle_analytics_post
from .api_key_protector import api_key_protector
from .dashboard import handle_dashboard_api
from .search.getTags import handle_get_tags
from .signin import handle_emailpassword_signin_api
from .signout import handle_emailpassword_signout_api
from .userdetails.user_delete import handle_user_delete
from .userdetails.user_email_verify_get import handle_user_email_verify_get
from .userdetails.user_email_verify_put import handle_user_email_verify_put
from .userdetails.user_email_verify_token_post import handle_email_verify_token_post
from .userdetails.user_get import handle_user_get
from .userdetails.user_metadata_get import handle_metadata_get
from .userdetails.user_metadata_put import handle_metadata_put
from .userdetails.user_password_put import handle_user_password_put
from .userdetails.user_put import handle_user_put
from .userdetails.user_sessions_get import handle_sessions_get
from .userdetails.user_sessions_post import handle_user_sessions_post
from .users_count_get import handle_users_count_get_api
from .users_get import handle_users_get_api
from .validate_key import handle_validate_key_api
from .list_tenants import handle_list_tenants_api

__all__ = [
    "handle_dashboard_api",
    "api_key_protector",
    "handle_users_count_get_api",
    "handle_users_get_api",
    "handle_validate_key_api",
    "handle_user_email_verify_get",
    "handle_user_get",
    "handle_metadata_get",
    "handle_sessions_get",
    "handle_user_delete",
    "handle_user_put",
    "handle_user_email_verify_put",
    "handle_metadata_put",
    "handle_user_sessions_post",
    "handle_user_password_put",
    "handle_email_verify_token_post",
    "handle_emailpassword_signin_api",
    "handle_emailpassword_signout_api",
    "handle_get_tags",
    "handle_analytics_post",
    "handle_list_tenants_api",
]
