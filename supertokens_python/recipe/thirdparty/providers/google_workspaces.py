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

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Union

from supertokens_python.recipe.thirdparty.api.implementation import (
    get_actual_client_id_from_development_client_id,
)
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdparty.types import (
    AccessTokenAPI,
    AuthorisationRedirectAPI,
    UserInfo,
    UserInfoEmail,
)
from supertokens_python.recipe.thirdparty.utils import (
    verify_id_token_from_jwks_endpoint,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest


class GoogleWorkspaces(Provider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scope: Union[None, List[str]] = None,
        domain: str = "*",
        authorisation_redirect: Union[
            None, Dict[str, Union[str, Callable[[BaseRequest], str]]]
        ] = None,
        is_default: bool = False,
    ):
        super().__init__("google-workspaces", is_default)
        default_scopes = ["https://www.googleapis.com/auth/userinfo.email"]
        self.domain = domain
        if scope is None:
            scope = default_scopes
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = list(set(scope))
        self.access_token_api_url = "https://accounts.google.com/o/oauth2/token"
        self.authorisation_redirect_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.authorisation_redirect_params = {}
        if authorisation_redirect is not None:
            self.authorisation_redirect_params = authorisation_redirect

    async def get_profile_info(
        self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        id_token: str = auth_code_response["id_token"]
        payload = verify_id_token_from_jwks_endpoint(
            id_token,
            "https://www.googleapis.com/oauth2/v3/certs",
            get_actual_client_id_from_development_client_id(self.client_id),
            ["https://accounts.google.com", "accounts.google.com"],
        )
        if "email" not in payload or payload["email"] is None:
            raise Exception("Could not get email. Please use a different login method")

        if "hd" not in payload or payload["hd"] is None:
            raise Exception("Please use a Google Workspace ID to login")

        # if the domain is "*" in it, it means that any workspace email is
        # allowed.
        if "*" not in self.domain and payload["hd"] != self.domain:
            raise Exception("Please use emails from " + self.domain + " to login")

        user_id = payload["sub"]
        if "email" not in payload or payload["email"] is None:
            return UserInfo(user_id)
        is_email_verified = (
            payload["email_verified"] if "email_verified" in payload else False
        )
        return UserInfo(user_id, UserInfoEmail(payload["email"], is_email_verified))

    def get_authorisation_redirect_api_info(
        self, user_context: Dict[str, Any]
    ) -> AuthorisationRedirectAPI:
        params = {
            "scope": " ".join(self.scopes),
            "response_type": "code",
            "client_id": self.client_id,
            "access_type": "offline",
            "include_granted_scopes": "true",
            "hd": self.domain,
            **self.authorisation_redirect_params,
        }
        return AuthorisationRedirectAPI(self.authorisation_redirect_url, params)

    def get_access_token_api_info(
        self,
        redirect_uri: str,
        auth_code_from_request: str,
        user_context: Dict[str, Any],
    ) -> AccessTokenAPI:
        params = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": auth_code_from_request,
            "redirect_uri": redirect_uri,
        }
        return AccessTokenAPI(self.access_token_api_url, params)

    def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]:
        return None

    def get_client_id(self, user_context: Dict[str, Any]) -> str:
        return self.client_id
