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

import re
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
from urllib.parse import quote, unquote_plus, urlencode, urlsplit

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.thirdparty.provider import ProviderInput

from .interfaces import APIInterface, RecipeInterface

if TYPE_CHECKING:
    from .provider import ProviderInput

from jwt import PyJWKClient, decode  # type: ignore


class SignInAndUpFeature:
    def __init__(self, providers: Optional[List[ProviderInput]] = None):
        if providers is None:
            providers = []

        third_party_id_set: Set[str] = set()

        for provider in providers:
            third_party_id = provider.config.third_party_id

            if third_party_id in third_party_id_set:
                raise_bad_input_exception(
                    "The providers array has multiple entries for the same third party provider."
                )

            third_party_id_set.add(third_party_id)

        self.providers = providers


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


TypeIsValidFrontendRedirectURIFunction = Callable[
    [str, BaseRequest, Dict[str, Any]], Union[bool, Awaitable[bool]]
]
"""
Decides whether the Apple form_post callback may redirect the user to the frontend redirect URI
(taken from the `state` sent to Apple). Called with the frontend redirect URI, the request and
the user context. If set, this replaces the default check, which only allows absolute http(s)
URLs whose scheme, host and port match the configured `origin` / `website_domain`.

Set this if your `origin` depends on the request (the callback arrives as a POST from Apple, so
request based origin resolution may not identify your frontend), if one backend serves several
frontends, or to allow other redirect targets, such as https universal/app links or custom-scheme
mobile deep links (e.g. `myapp://callback`).

Returning `True` allows the redirect, returning `False` rejects the request with a 400 and no
redirect. Exceptions raised by this function are propagated and no redirect is done. The function
may be sync or async.

The function is only called for absolute URLs. http(s) URLs must have a host, and `javascript:`,
`data:`, `vbscript:`, `file:`, `blob:`, `about:` and `filesystem:` URLs are always rejected
without calling it. Browsers and Python's URL parsing can disagree on where some URLs point, and a
Location header can't carry a non-ASCII host, so these are always rejected without calling it too:

- URLs containing a backslash, whitespace or a control character,
- http(s) URLs with a username or password (e.g. `https://user@app.example.com/`),
- http(s) URLs with a non-ASCII host: use its punycode form instead, as browsers do (e.g.
  `https://xn--bcher-kva.example/` instead of `https://bücher.example/`).

The frontend redirect URI is passed in the normalised form we redirect to, without the fields
Apple posted, which are added to its query afterwards: the scheme is lowercased, for http(s) URLs
the host is lowercased, a default port is dropped and an empty path becomes `/`, dot segments
(`.` and `..`, also written as `%2e`) are removed from paths that start with `/`, and non-ASCII
characters are percent-encoded (as UTF-8). For example, `HTTPS://App.Example.com/a/../cb` is passed
as `https://app.example.com/cb`.

The whole `state` is chosen by whoever starts the sign in, so treat the URI as untrusted. Parse it
(e.g. with `urllib.parse.urlsplit`) and compare its parts, such as the scheme, host, port and path,
with the values you allow, instead of comparing it as a string. In particular, don't use prefix or
substring checks: for example, `https://app.example.com.evil.test/` starts with
`https://app.example.com`, and in `intent://callback#Intent;package=...;end` the receiving app is
chosen by the fragment.

The redirect carries the authorization code and the `id_token` from Apple. Custom URL schemes are
not owned by a single app: any app installed on the device can register the same scheme and receive
them. Prefer verified https universal / app links for mobile redirects where possible.
"""


class ThirdPartyConfig:
    def __init__(
        self,
        sign_in_and_up_feature: SignInAndUpFeature,
        override: OverrideConfig,
        is_valid_frontend_redirect_uri: Optional[
            TypeIsValidFrontendRedirectURIFunction
        ] = None,
    ):
        self.sign_in_and_up_feature = sign_in_and_up_feature
        self.override = override
        self.is_valid_frontend_redirect_uri = is_valid_frontend_redirect_uri


def validate_and_normalise_user_input(
    sign_in_and_up_feature: SignInAndUpFeature,
    override: Union[InputOverrideConfig, None] = None,
    is_valid_frontend_redirect_uri: Optional[
        TypeIsValidFrontendRedirectURIFunction
    ] = None,
) -> ThirdPartyConfig:
    if not isinstance(sign_in_and_up_feature, SignInAndUpFeature):  # type: ignore
        raise ValueError(
            "sign_in_and_up_feature must be an instance of SignInAndUpFeature"
        )

    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be an instance of InputOverrideConfig or None")

    if is_valid_frontend_redirect_uri is not None and not callable(
        is_valid_frontend_redirect_uri
    ):
        raise ValueError("is_valid_frontend_redirect_uri must be a function or None")

    if override is None:
        override = InputOverrideConfig()

    return ThirdPartyConfig(
        sign_in_and_up_feature,
        OverrideConfig(functions=override.functions, apis=override.apis),
        is_valid_frontend_redirect_uri,
    )


def verify_id_token_from_jwks_endpoint(
    id_token: str, jwks_uri: str, audience: str, issuers: List[str]
) -> Dict[str, Any]:
    jwks_client = PyJWKClient(jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    data: Dict[str, Any] = decode(  # type: ignore
        id_token,
        signing_key.key,  # type: ignore
        algorithms=["RS256"],
        audience=audience,
        options={"verify_exp": False},
    )

    issuer_found = False
    for issuer in issuers:
        if data["iss"] == issuer:
            issuer_found = True

    if not issuer_found:
        raise Exception("no required issuer found")

    return data


def get_normalised_origin_tuple(
    url: str, convert_idn_host: bool = False
) -> Optional[Tuple[str, str, int]]:
    """
    Returns the (scheme, lowercased hostname, port) tuple of an absolute http(s) URL,
    filling in the default port if it is not explicit. Returns None if the input is not
    such a URL.

    URLs containing a backslash, whitespace or a control character, or with a userinfo
    part, are rejected: browsers and urllib can disagree on which host they point to.

    If `convert_idn_host` is set (we do this for the configured origin), a non-ASCII host is
    converted to its IDNA A-label (punycode) form, which is how browsers send it, and None is
    returned if that isn't possible. Otherwise URLs with a non-ASCII host are rejected.
    """
    if has_unsafe_url_characters(url):
        return None

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        return None

    hostname = parsed.hostname
    if not hostname.isascii():
        # A Location header can't carry a non-ASCII host, so we don't accept those in redirect
        # targets
        if not convert_idn_host:
            return None
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    if parsed.username is not None or parsed.password is not None:
        return None

    if port is None:
        port = 443 if scheme == "https" else 80

    return scheme, hostname.lower(), port


def is_http_url_with_userinfo(url: str) -> bool:
    """
    Returns whether the URL is an http(s) URL with a userinfo part (a username or password),
    which `get_normalised_origin_tuple` rejects. URLs containing a backslash, whitespace or a
    control character are rejected for those characters instead, so this returns False for them.
    """
    if has_unsafe_url_characters(url):
        return False

    try:
        parsed = urlsplit(url)
    except ValueError:
        return False

    return parsed.scheme.lower() in ("http", "https") and (
        parsed.username is not None or parsed.password is not None
    )


# Schemes that are never allowed as a redirect target, even if the app allows the URL
DISALLOWED_REDIRECT_SCHEMES = {
    "javascript",
    "data",
    "vbscript",
    "file",
    "blob",
    "about",
    "filesystem",
}


def has_unsafe_url_characters(url: str) -> bool:
    return any(c == "\\" or c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in url)


def is_allowed_custom_redirect_target(url: str) -> bool:
    """
    Checks the redirect targets that an app-provided check may allow: absolute URLs whose
    scheme isn't one of `DISALLOWED_REDIRECT_SCHEMES`. http(s) URLs must also pass
    `get_normalised_origin_tuple`.
    """
    if has_unsafe_url_characters(url):
        return False

    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return False

    if scheme == "":
        return False

    if scheme in ("http", "https"):
        return get_normalised_origin_tuple(url) is not None

    return scheme not in DISALLOWED_REDIRECT_SCHEMES


# The part of a URL after `<scheme>:`, split into the authority (with its `//`), the path, the query
# (with its `?`) and the fragment (with its `#`), as in RFC 3986 appendix B. Every string matches.
URL_AFTER_SCHEME_REGEX = re.compile(r"(//[^/?#]*)?([^?#]*)(\?[^#]*)?(#.*)?", re.DOTALL)


def normalise_frontend_redirect_uri(url: str) -> str:
    """
    Returns the form of an already validated redirect target that we redirect to:

    - the scheme is lowercased,
    - for http(s) URLs, the host is lowercased, a default port is dropped and an empty path
      becomes `/`,
    - dot segments (`.` and `..`, also written as `%2e`) are removed from paths that start with
      `/`, as in RFC 3986 section 5.2.4 (e.g. `https://app.example.com/a/../cb` becomes
      `https://app.example.com/cb`),
    - non-ASCII characters are percent-encoded (as UTF-8) everywhere except the scheme and the
      host of http(s) URLs.

    Everything else is kept as written, including an empty query (`?`) or fragment (`#`).
    """
    scheme = urlsplit(url).scheme
    match = URL_AFTER_SCHEME_REGEX.fullmatch(url[len(scheme) + 1 :])
    assert match is not None
    authority: str = match.group(1) or ""
    path: str = match.group(2) or ""
    query: str = match.group(3) or ""
    fragment: str = match.group(4) or ""

    scheme = scheme.lower()
    if scheme in ("http", "https"):
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        port = parsed.port
        authority = f"//{hostname}"
        if port is not None and port != (443 if scheme == "https" else 80):
            authority += f":{port}"
        path = path or "/"
    else:
        authority = percent_encode_non_ascii(authority)

    if path.startswith("/"):
        path = remove_dot_segments(path)
        if authority == "" and path.startswith("//"):
            # Without an authority, a path starting with `//` would be read as one
            path = f"/.{path}"

    return f"{scheme}:{authority}{percent_encode_non_ascii(path + query + fragment)}"


SINGLE_DOT_SEGMENTS = {".", "%2e"}
DOUBLE_DOT_SEGMENTS = {"..", ".%2e", "%2e.", "%2e%2e"}


def remove_dot_segments(path: str) -> str:
    """
    Removes the `.` and `..` segments from a path that starts with `/`, as in RFC 3986 section
    5.2.4. Like browsers, it treats `%2e` (in any case) as `.`.
    """
    output: List[str] = []
    segments = path[1:].split("/")
    for i, segment in enumerate(segments):
        is_last = i == len(segments) - 1
        if segment.lower() in SINGLE_DOT_SEGMENTS:
            if is_last:
                output.append("")
        elif segment.lower() in DOUBLE_DOT_SEGMENTS:
            if output:
                output.pop()
            if is_last:
                output.append("")
        else:
            output.append(segment)
    return "/" + "/".join(output)


def percent_encode_non_ascii(value: str) -> str:
    """Percent-encodes (as UTF-8) the non-ASCII characters of a URL part, keeping everything else as it is"""
    return "".join(c if c.isascii() else quote(c, safe="") for c in value)


def add_query_params(url: str, params: Dict[str, str]) -> str:
    """
    Adds the given params to the query of the URL. The existing query is kept as written, except
    for params with the same names as the added ones, which are removed. The path and the fragment
    are kept as they are.
    """
    url_without_fragment, hash_sign, fragment = url.partition("#")
    base, _, query = url_without_fragment.partition("?")

    kept_query_parts = [
        part
        for part in query.split("&")
        if part != "" and unquote_plus(part.partition("=")[0]) not in params
    ]
    query_parts = kept_query_parts + ([urlencode(params)] if params else [])

    return f"{base}?{'&'.join(query_parts)}{hash_sign}{fragment}"
