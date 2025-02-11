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


from typing import Any, Dict, List, Optional


class OAuth2Client:
    # OAuth 2.0 Client ID
    # The ID is immutable. If no ID is provided, a UUID4 will be generated.
    client_id: str

    # OAuth 2.0 Client Name
    # The human-readable name of the client to be presented to the end-user during authorization.
    client_name: str

    # OAuth 2.0 Client Scope
    # Scope is a string containing a space-separated list of scope values that the client
    # can use when requesting access tokens.
    scope: str

    # OAuth 2.0 Token Endpoint Authentication Method
    # Requested Client Authentication method for the Token Endpoint.
    token_endpoint_auth_method: str

    # OAuth 2.0 Client Creation Date
    # CreatedAt returns the timestamp of the client's creation.
    created_at: str

    # OAuth 2.0 Client Last Update Date
    # UpdatedAt returns the timestamp of the last update.
    updated_at: str

    # OAuth 2.0 Client Secret
    client_secret: Optional[str] = None

    # Array of redirect URIs
    redirect_uris: Optional[List[str]] = None

    # Array of post logout redirect URIs
    post_logout_redirect_uris: Optional[List[str]] = None

    # Authorization Code Grant Access Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    authorization_code_grant_access_token_lifespan: Optional[str] = None

    # Authorization Code Grant ID Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    authorization_code_grant_id_token_lifespan: Optional[str] = None

    # Authorization Code Grant Refresh Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    authorization_code_grant_refresh_token_lifespan: Optional[str] = None

    # Client Credentials Grant Access Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    client_credentials_grant_access_token_lifespan: Optional[str] = None

    # Implicit Grant Access Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    implicit_grant_access_token_lifespan: Optional[str] = None

    # Implicit Grant ID Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    implicit_grant_id_token_lifespan: Optional[str] = None

    # Refresh Token Grant Access Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    refresh_token_grant_access_token_lifespan: Optional[str] = None

    # Refresh Token Grant ID Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    refresh_token_grant_id_token_lifespan: Optional[str] = None

    # Refresh Token Grant Refresh Token Lifespan
    # NullDuration - ^[0-9]+(ns|us|ms|s|m|h)$
    refresh_token_grant_refresh_token_lifespan: Optional[str] = None

    # OAuth 2.0 Client URI
    # ClientURI is a URL string of a web page providing information about the client.
    client_uri: str = ""

    # Array of audiences
    audience: List[str] = []

    # Array of grant types
    grant_types: Optional[List[str]] = None

    # Array of response types
    response_types: Optional[List[str]] = None

    # OAuth 2.0 Client Logo URI
    # A URL string referencing the client's logo.
    logo_uri: str = ""

    # OAuth 2.0 Client Policy URI
    # PolicyURI is a URL string that points to a human-readable privacy policy document
    # that describes how the deployment organization collects, uses,
    # retains, and discloses personal data.
    policy_uri: str = ""

    # OAuth 2.0 Client Terms of Service URI
    # A URL string pointing to a human-readable terms of service
    # document for the client that describes a contractual relationship
    # between the end-user and the client that the end-user accepts when
    # authorizing the client.
    tos_uri: str = ""

    # Metadata - JSON object
    metadata: Dict[str, Any] = {}

    # This flag is set to true if refresh tokens are updated upon use
    enable_refresh_token_rotation: bool = False

    def __init__(
        self,
        client_id: str,
        client_name: str,
        scope: str,
        token_endpoint_auth_method: str,
        created_at: str,
        updated_at: str,
        client_secret: Optional[str],
        redirect_uris: Optional[List[str]],
        post_logout_redirect_uris: Optional[List[str]],
        authorization_code_grant_access_token_lifespan: Optional[str],
        authorization_code_grant_id_token_lifespan: Optional[str],
        authorization_code_grant_refresh_token_lifespan: Optional[str],
        client_credentials_grant_access_token_lifespan: Optional[str],
        implicit_grant_access_token_lifespan: Optional[str],
        implicit_grant_id_token_lifespan: Optional[str],
        refresh_token_grant_access_token_lifespan: Optional[str],
        refresh_token_grant_id_token_lifespan: Optional[str],
        refresh_token_grant_refresh_token_lifespan: Optional[str],
        client_uri: str,
        audience: List[str],
        grant_types: Optional[List[str]],
        response_types: Optional[List[str]],
        logo_uri: str,
        policy_uri: str,
        tos_uri: str,
        metadata: Dict[str, Any],
        enable_refresh_token_rotation: bool,
    ):
        self.client_id = client_id
        self.client_name = client_name
        self.scope = scope
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.created_at = created_at
        self.updated_at = updated_at
        self.client_secret = client_secret
        self.redirect_uris = redirect_uris
        self.post_logout_redirect_uris = post_logout_redirect_uris
        self.authorization_code_grant_access_token_lifespan = (
            authorization_code_grant_access_token_lifespan
        )
        self.authorization_code_grant_id_token_lifespan = (
            authorization_code_grant_id_token_lifespan
        )
        self.authorization_code_grant_refresh_token_lifespan = (
            authorization_code_grant_refresh_token_lifespan
        )
        self.client_credentials_grant_access_token_lifespan = (
            client_credentials_grant_access_token_lifespan
        )
        self.implicit_grant_access_token_lifespan = implicit_grant_access_token_lifespan
        self.implicit_grant_id_token_lifespan = implicit_grant_id_token_lifespan
        self.refresh_token_grant_access_token_lifespan = (
            refresh_token_grant_access_token_lifespan
        )
        self.refresh_token_grant_id_token_lifespan = (
            refresh_token_grant_id_token_lifespan
        )
        self.refresh_token_grant_refresh_token_lifespan = (
            refresh_token_grant_refresh_token_lifespan
        )
        self.client_uri = client_uri
        self.audience = audience
        self.grant_types = grant_types
        self.response_types = response_types
        self.logo_uri = logo_uri
        self.policy_uri = policy_uri
        self.tos_uri = tos_uri
        self.metadata = metadata
        self.enable_refresh_token_rotation = enable_refresh_token_rotation

    @staticmethod
    def from_json(json: Dict[str, Any]) -> "OAuth2Client":
        # Transform keys from snake_case to camelCase
        return OAuth2Client(
            client_id=json["clientId"],
            client_secret=json.get("clientSecret"),
            client_name=json["clientName"],
            scope=json["scope"],
            redirect_uris=json.get("redirectUris"),
            post_logout_redirect_uris=json.get("postLogoutRedirectUris"),
            authorization_code_grant_access_token_lifespan=json.get(
                "authorizationCodeGrantAccessTokenLifespan"
            ),
            authorization_code_grant_id_token_lifespan=json.get(
                "authorizationCodeGrantIdTokenLifespan"
            ),
            authorization_code_grant_refresh_token_lifespan=json.get(
                "authorizationCodeGrantRefreshTokenLifespan"
            ),
            client_credentials_grant_access_token_lifespan=json.get(
                "clientCredentialsGrantAccessTokenLifespan"
            ),
            implicit_grant_access_token_lifespan=json.get(
                "implicitGrantAccessTokenLifespan"
            ),
            implicit_grant_id_token_lifespan=json.get("implicitGrantIdTokenLifespan"),
            refresh_token_grant_access_token_lifespan=json.get(
                "refreshTokenGrantAccessTokenLifespan"
            ),
            refresh_token_grant_id_token_lifespan=json.get(
                "refreshTokenGrantIdTokenLifespan"
            ),
            refresh_token_grant_refresh_token_lifespan=json.get(
                "refreshTokenGrantRefreshTokenLifespan"
            ),
            token_endpoint_auth_method=json["tokenEndpointAuthMethod"],
            client_uri=json.get("clientUri", ""),
            audience=json.get("audience", []),
            grant_types=json.get("grantTypes"),
            response_types=json.get("responseTypes"),
            logo_uri=json.get("logoUri", ""),
            policy_uri=json.get("policyUri", ""),
            tos_uri=json.get("tosUri", ""),
            created_at=json["createdAt"],
            updated_at=json["updatedAt"],
            metadata=json.get("metadata", {}),
            enable_refresh_token_rotation=json.get("enableRefreshTokenRotation", False),
        )

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "clientId": self.client_id,
            "clientName": self.client_name,
            "scope": self.scope,
            "tokenEndpointAuthMethod": self.token_endpoint_auth_method,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "clientUri": self.client_uri,
            "audience": self.audience,
            "logoUri": self.logo_uri,
            "policyUri": self.policy_uri,
            "tosUri": self.tos_uri,
            "metadata": self.metadata,
            "enableRefreshTokenRotation": self.enable_refresh_token_rotation,
        }

        if self.client_secret is not None:
            result["clientSecret"] = self.client_secret
        result["redirectUris"] = self.redirect_uris
        if self.post_logout_redirect_uris is not None:
            result["postLogoutRedirectUris"] = self.post_logout_redirect_uris
        result["authorizationCodeGrantAccessTokenLifespan"] = (
            self.authorization_code_grant_access_token_lifespan
        )
        result["authorizationCodeGrantIdTokenLifespan"] = (
            self.authorization_code_grant_id_token_lifespan
        )
        result["authorizationCodeGrantRefreshTokenLifespan"] = (
            self.authorization_code_grant_refresh_token_lifespan
        )
        result["clientCredentialsGrantAccessTokenLifespan"] = (
            self.client_credentials_grant_access_token_lifespan
        )
        result["implicitGrantAccessTokenLifespan"] = (
            self.implicit_grant_access_token_lifespan
        )
        result["implicitGrantIdTokenLifespan"] = self.implicit_grant_id_token_lifespan
        result["refreshTokenGrantAccessTokenLifespan"] = (
            self.refresh_token_grant_access_token_lifespan
        )
        result["refreshTokenGrantIdTokenLifespan"] = (
            self.refresh_token_grant_id_token_lifespan
        )
        result["refreshTokenGrantRefreshTokenLifespan"] = (
            self.refresh_token_grant_refresh_token_lifespan
        )
        result["grantTypes"] = self.grant_types
        result["responseTypes"] = self.response_types

        return result
