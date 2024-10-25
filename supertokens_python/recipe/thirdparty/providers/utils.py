from typing import Any, Dict, Optional, Tuple

from httpx import AsyncClient

from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath

DEV_OAUTH_CLIENT_IDS = [
    "1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
    # google client id
    "467101b197249757c71f",  # github client id
]
DEV_KEY_IDENTIFIER = "4398792-"
DEV_OAUTH_AUTHORIZATION_URL = "https://supertokens.io/dev/oauth/redirect-to-provider"
DEV_OAUTH_REDIRECT_URL = "https://supertokens.io/dev/oauth/redirect-to-app"


def is_using_oauth_development_client_id(client_id: str):
    return client_id.startswith(DEV_KEY_IDENTIFIER) or client_id in DEV_OAUTH_CLIENT_IDS


def get_actual_client_id_from_development_client_id(client_id: str) -> str:
    if client_id.startswith(DEV_KEY_IDENTIFIER):
        return client_id.split(DEV_KEY_IDENTIFIER, 1)[1]
    return client_id


async def do_get_request(
    url: str,
    query_params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if query_params is None:
        query_params = {}
    if headers is None:
        headers = {}

    async with AsyncClient(timeout=30.0) as client:
        res = await client.get(url, params=query_params, headers=headers)  # type:ignore

        log_debug_message(
            "Received response with status %s and body %s", res.status_code, res.text
        )

        return res.json()


async def do_post_request(
    url: str,
    body_params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, Any]]:
    if body_params is None:
        body_params = {}
    if headers is None:
        headers = {}

    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["accept"] = "application/json"

    async with AsyncClient(timeout=30.0) as client:
        res = await client.post(url, data=body_params, headers=headers)  # type:ignore
        log_debug_message(
            "Received response with status %s and body %s", res.status_code, res.text
        )
        try:
            return res.status_code, res.json()
        except Exception:
            return res.status_code, {"message": res.text}


def normalise_oidc_endpoint_to_include_well_known(url: str) -> str:
    # We call this only for built-in providers that use OIDC.
    # We no longer generically add well-known in the custom provider
    if url.endswith("/.well-known/openid-configuration"):
        return url

    try:
        normalised_domain = NormalisedURLDomain(url)
        normalised_path = NormalisedURLPath(url)

        normalised_path = normalised_path.append(
            NormalisedURLPath("/.well-known/openid-configuration")
        )
    except Exception:
        return url  # Return original URL if normalization fails

    return (
        normalised_domain.get_as_string_dangerous()
        + normalised_path.get_as_string_dangerous()
    )
