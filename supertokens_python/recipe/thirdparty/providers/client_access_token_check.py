# Copyright (c) 2026, VRAI Labs and/or its affiliates. All rights reserved.
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
"""
Checks that access tokens sent by the client to the sign in up API (in `oAuthTokens`) were issued to one of the
provider's clients, before the user info is fetched with them.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Set, Tuple

from httpx import AsyncClient

from supertokens_python.logger import log_debug_message

from ..provider import ProviderConfigForClient, RedirectUriInfo
from ..types import UserInfo
from .custom import GenericProvider
from .utils import get_actual_client_id_from_development_client_id

ACCESS_TOKEN_DOES_NOT_BELONG_TO_APP = "Access token does not belong to your application"


class ProviderWithClientAccessTokenCheck(GenericProvider):
    """
    Before the user info is fetched with an access token that the client sent, calls check_client_access_token.

    The check is skipped:
    - if validate_access_token is set in the provider config (get_user_info runs that instead, as before)
    - for the access token the SDK got itself, by exchanging an authorisation code with the provider. This works
      because a new provider instance is created for every request.
    """

    _access_token_from_code_exchange: Optional[str] = None

    async def check_client_access_token(
        self, access_token: str, client_ids: Set[str]
    ) -> None:
        raise NotImplementedError()

    async def exchange_auth_code_for_oauth_tokens(
        self, redirect_uri_info: RedirectUriInfo, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        oauth_tokens = await super().exchange_auth_code_for_oauth_tokens(
            redirect_uri_info, user_context
        )
        access_token = oauth_tokens.get("access_token")
        if isinstance(access_token, str):
            self._access_token_from_code_exchange = access_token
        return oauth_tokens

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        access_token = oauth_tokens.get("access_token")
        if (
            self.config.validate_access_token is None
            and isinstance(access_token, str)
            and access_token != self._access_token_from_code_exchange
        ):
            await self.check_client_access_token(access_token, self._get_client_ids())
        return await super().get_user_info(oauth_tokens, user_context)

    def _get_client_ids(self) -> Set[str]:
        """The client ids of every client of the provider (for this tenant)"""
        client_ids: Set[str] = set()
        for client in self.input_config.clients or []:
            if client.client_id:
                client_ids.add(
                    get_actual_client_id_from_development_client_id(client.client_id)
                )
        if self.config.client_id:
            client_ids.add(
                get_actual_client_id_from_development_client_id(self.config.client_id)
            )
        return client_ids


def _is_one_of(value: Any, client_ids: Set[str]) -> bool:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return False
    return str(value) in client_ids


async def _do_access_token_check_request(
    method: str,
    url: str,
    query_params: Optional[Dict[str, str]] = None,
    form_params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Optional[Dict[str, Any]]]:
    """
    We don't log the query params, the headers or the response body of these requests, since they contain the
    access token (and for Facebook, the client secret).
    """
    request_headers = {"accept": "application/json", **(headers or {})}
    log_debug_message(
        "%s request to %s to check an access token sent by the client", method, url
    )
    async with AsyncClient(timeout=30.0) as client:
        res = await client.request(  # type: ignore
            method,
            url,
            params=query_params,
            data=form_params,
            headers=request_headers,
        )
    log_debug_message("Received response with status %s", res.status_code)

    # Error responses are parsed too: Facebook's error body tells a token of another app apart from a config problem
    body: Optional[Dict[str, Any]] = None
    try:
        parsed = res.json()
        if isinstance(parsed, dict):
            body = parsed  # type: ignore
    except Exception:
        body = None
    return res.status_code, body


def _raise_for_failed_check(
    provider_name: str, status: int, invalid_token_statuses: Tuple[int, ...]
) -> None:
    if status in invalid_token_statuses:
        raise ValueError("Invalid access token")
    raise ValueError(
        f"Could not check the access token with {provider_name} (status {status})"
    )


async def check_google_access_token(access_token: str, client_ids: Set[str]) -> None:
    """
    Google's token info API returns the client the token is for (aud) and the client that requested it (azp).
    They can differ, e.g. for tokens requested on Android or iOS for another client of the same Google Cloud
    project.
    """
    status, body = await _do_access_token_check_request(
        "POST",
        "https://oauth2.googleapis.com/tokeninfo",
        form_params={"access_token": access_token},
    )
    if status != 200 or body is None:
        _raise_for_failed_check("Google", status, (400, 401))
        return
    if not _is_one_of(body.get("aud"), client_ids) and not _is_one_of(
        body.get("azp"), client_ids
    ):
        raise ValueError(ACCESS_TOKEN_DOES_NOT_BELONG_TO_APP)


def _is_facebook_error_for_token_of_another_app(body: Optional[Dict[str, Any]]) -> bool:
    """
    Facebook doesn't debug a token of another app: it answers with error 100, "The App_id in the input_token did
    not match the Viewing App", instead of returning the token's app_id.
    """
    error = body.get("error") if body is not None else None
    if not isinstance(error, dict):
        return False
    message = error.get("message")  # type: ignore
    return (
        error.get("code") == 100  # type: ignore
        and isinstance(message, str)
        and "did not match the viewing app" in message.lower()
    )


async def check_facebook_access_token(
    access_token: str, client_config: ProviderConfigForClient, client_ids: Set[str]
) -> None:
    """Facebook's debug token API needs an app access token, made from the client id and the client secret."""
    if client_config.client_secret is None:
        raise ValueError(
            "The Facebook provider needs the client_secret of the client to check access tokens sent in "
            "oAuthTokens. Please add it to the provider config, or set a custom validate_access_token."
        )
    client_id = get_actual_client_id_from_development_client_id(client_config.client_id)
    status, body = await _do_access_token_check_request(
        "GET",
        "https://graph.facebook.com/debug_token",
        query_params={
            "input_token": access_token,
            "access_token": f"{client_id}|{client_config.client_secret}",
        },
    )
    data = body.get("data") if body is not None else None
    if status != 200 or not isinstance(data, dict):
        if _is_facebook_error_for_token_of_another_app(body):
            raise ValueError(ACCESS_TOKEN_DOES_NOT_BELONG_TO_APP)
        raise ValueError(
            f"Could not check the access token with Facebook (status {status}). "
            "Please check the client_id and client_secret of the Facebook provider."
        )
    if data.get("is_valid") is not True:  # type: ignore
        raise ValueError("Invalid access token")
    if not _is_one_of(data.get("app_id"), client_ids):  # type: ignore
        raise ValueError(ACCESS_TOKEN_DOES_NOT_BELONG_TO_APP)


async def check_gitlab_access_token(
    access_token: str, client_config: ProviderConfigForClient, client_ids: Set[str]
) -> None:
    """GitLab's token info API returns the application (client id) the token was issued to."""
    status, body = await _do_access_token_check_request(
        "GET",
        _get_gitlab_base_url(client_config) + "/oauth/token/info",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if status != 200 or body is None:
        _raise_for_failed_check("GitLab", status, (401,))
        return
    application = body.get("application")
    uid = application.get("uid") if isinstance(application, dict) else None  # type: ignore
    if not _is_one_of(uid, client_ids):
        raise ValueError(ACCESS_TOKEN_DOES_NOT_BELONG_TO_APP)


def _get_gitlab_base_url(client_config: ProviderConfigForClient) -> str:
    well_known_suffix = "/.well-known/openid-configuration"
    discovery_endpoint = client_config.oidc_discovery_endpoint
    if discovery_endpoint is not None and discovery_endpoint.endswith(
        well_known_suffix
    ):
        return discovery_endpoint[: -len(well_known_suffix)]
    return "https://gitlab.com"


async def check_discord_access_token(access_token: str, client_ids: Set[str]) -> None:
    """
    Discord's current authorization API returns the application the token was issued to. Discord's client id is
    the application's id.
    """
    status, body = await _do_access_token_check_request(
        "GET",
        "https://discord.com/api/oauth2/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if status != 200 or body is None:
        _raise_for_failed_check("Discord", status, (401,))
        return
    application = body.get("application")
    app_id = application.get("id") if isinstance(application, dict) else None  # type: ignore
    if not _is_one_of(app_id, client_ids):
        raise ValueError(ACCESS_TOKEN_DOES_NOT_BELONG_TO_APP)
