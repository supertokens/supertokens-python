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
Plan 4 regression tests:

- N7: api/auth.py and api/login.py call set_cookie with `expires=...`
  derived from the cookie's `Expires` attribute. When the attribute is
  missing or unparseable, the previous code crashed with `ValueError`
  because `dateutil.parser.parse("")` raises. The shared helper
  `parse_expires_ms_or_default` now falls back to a 1-hour TTL.

- N8: get_merged_cookies must drop cookies whose `Expires` is in the
  past (the OAuth core's idiom for "delete this cookie") instead of
  retaining the value, matching Node's setCookieParser behavior.
"""

import time

from supertokens_python.recipe.oauth2provider.api.utils import (
    get_merged_cookies,
    parse_expires_ms_or_default,
)


def test_parse_expires_ms_or_default_with_empty_string_returns_fallback():
    before = time.time()
    result = parse_expires_ms_or_default("")
    after = time.time()
    # Result is in ms; should be roughly now + 1 hour.
    assert before * 1000 + 3500 * 1000 < result < after * 1000 + 3700 * 1000


def test_parse_expires_ms_or_default_with_unparseable_returns_fallback():
    before = time.time()
    result = parse_expires_ms_or_default("not-a-real-date")
    after = time.time()
    assert before * 1000 + 3500 * 1000 < result < after * 1000 + 3700 * 1000


def test_parse_expires_ms_or_default_with_valid_date():
    # A specific UTC date.
    result = parse_expires_ms_or_default("Wed, 01 Jan 2025 00:00:00 GMT")
    # 2025-01-01 00:00:00 UTC == 1735689600 seconds since epoch.
    assert result == 1735689600 * 1000


def test_get_merged_cookies_keeps_cookie_with_no_expires_attribute():
    """A cookie without an Expires attribute should be retained — it's a
    session cookie, not a 'delete this cookie' instruction."""
    merged = get_merged_cookies(
        orig_cookies="other_cookie=other_value",
        new_cookies=["hydra_login_csrf=token-value; Path=/"],
    )

    assert "hydra_login_csrf=token-value" in merged
    assert "other_cookie=other_value" in merged


def test_get_merged_cookies_drops_cookie_when_expires_is_in_past():
    """The OAuth core signals 'delete this cookie' by setting Expires in the
    past. get_merged_cookies must honor that and remove the cookie from the
    map, so the redirect chain reflects the core's intent.

    Previously Python only looked at the first `name=value` segment and
    ignored attributes entirely, so logout cookies survived the merge.
    """
    merged = get_merged_cookies(
        orig_cookies="hydra_login_csrf=existing-value; other=keep",
        new_cookies=[
            "hydra_login_csrf=ignored; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        ],
    )

    assert "hydra_login_csrf=" not in merged
    assert "other=keep" in merged


def test_get_merged_cookies_overwrites_when_expires_is_in_future():
    merged = get_merged_cookies(
        orig_cookies="hydra_login_csrf=old-value",
        new_cookies=[
            "hydra_login_csrf=new-value; Path=/; Expires=Wed, 01 Jan 2099 00:00:00 GMT"
        ],
    )

    assert "hydra_login_csrf=new-value" in merged
    assert "hydra_login_csrf=old-value" not in merged


def test_get_merged_cookies_with_no_new_cookies_is_passthrough():
    assert get_merged_cookies("a=1; b=2", None) == "a=1; b=2"
    assert get_merged_cookies("a=1; b=2", []) == "a=1; b=2"
