# Copyright (c) 2023, VRAI Labs and/or its affiliates. All rights reserved.
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

import threading
from os import environ
from typing import List, Optional

import requests
from jwt import PyJWK, PyJWKSet
from typing_extensions import TypedDict

from supertokens_python.logger import log_debug_message
from supertokens_python.querier import Querier
from supertokens_python.recipe.session.utils import NormalisedSessionConfig
from supertokens_python.utils import RWLockContext, RWMutex, get_timestamp_ms


class JWKSConfigType(TypedDict):
    request_timeout: int


JWKSConfig: JWKSConfigType = {
    "request_timeout": 10000,  # 10s
}


class CachedKeys:
    def __init__(self, keys: List[PyJWK], refresh_interval_sec: int):
        self.keys = keys
        self.last_refresh_time = get_timestamp_ms()
        self.refresh_interval_sec = refresh_interval_sec

    def is_fresh(self):
        return (
            get_timestamp_ms() - self.last_refresh_time
            < self.refresh_interval_sec * 1000
        )


cached_keys: Optional[CachedKeys] = None
# Time of the last JWKS fetch from the core (successful or not)
last_fetch_time_ms: Optional[int] = None
# Guards cached_keys and last_fetch_time_ms
mutex = RWMutex()
# Makes sure only one thread fetches the JWKS at a time. It is held during the HTTP request, so it is
# separate from mutex, which would block every reader of the cache.
fetch_lock = threading.Lock()

# A token with a kid that is not in a fresh cache only triggers a new fetch if the last fetch
# happened at least this long ago.
JWKS_REFETCH_COOLDOWN_MS = 500


# only for testing purposes
def reset_jwks_cache():
    with RWLockContext(mutex, read=False):
        global cached_keys, last_fetch_time_ms
        cached_keys = None
        last_fetch_time_ms = None


def get_cached_keys() -> Optional[List[PyJWK]]:
    if cached_keys is not None:
        # This means that we have valid JWKs for the given core path
        # We check if we need to refresh before returning

        # This means that the value in cache is not expired, in this case we return the cached value
        # Note that this also means that the SDK will not try to query any other core (if there are multiple)
        # if it has a valid cache entry from one of the core URLs. It will only attempt to fetch
        # from the cores again after the entry in the cache is expired
        if cached_keys.is_fresh():
            return cached_keys.keys

    return None


def find_matching_keys(
    keys: Optional[List[PyJWK]], kid: Optional[str]
) -> Optional[List[PyJWK]]:
    if kid is None or keys is None:
        # return all keys since the token does not have a kid
        return keys

    # kid has been provided so filter the keys
    matching_keys = [key for key in keys if key.key_id == kid]  # type: ignore
    if len(matching_keys) > 0:
        return matching_keys

    return None


def find_matching_keys_in_cache(kid: Optional[str]) -> Optional[List[PyJWK]]:
    """Returns the matching keys from the cache, or None if the keys need to be fetched.

    Raises an exception if the cache is fresh but has no key matching the kid and the keys
    were fetched too recently to fetch them again.
    """
    with RWLockContext(mutex, read=True):
        keys = get_cached_keys()
        matching_keys = find_matching_keys(keys, kid)
        if matching_keys is not None:
            return matching_keys

        if (
            keys is not None
            and last_fetch_time_ms is not None
            and get_timestamp_ms() - last_fetch_time_ms < JWKS_REFETCH_COOLDOWN_MS
        ):
            log_debug_message(
                "Not fetching JWKS for an unknown kid because they were fetched recently"
            )
            raise Exception("No matching JWKS found")

    return None


def get_latest_keys(
    config: NormalisedSessionConfig, kid: Optional[str] = None
) -> List[PyJWK]:
    global cached_keys, last_fetch_time_ms

    if environ.get("SUPERTOKENS_ENV") == "testing":
        log_debug_message("Called find_jwk_client")

    matching_keys = find_matching_keys_in_cache(kid)
    if matching_keys is not None:
        if environ.get("SUPERTOKENS_ENV") == "testing":
            log_debug_message("Returning JWKS from cache")
        return matching_keys
    # otherwise unknown kid, will continue to reload the keys

    core_paths = Querier.get_instance().get_all_core_urls_for_path(
        "./.well-known/jwks.json"
    )

    if len(core_paths) == 0:
        raise Exception(
            "No SuperTokens core available to query. Please pass supertokens > connection_uri to the init function, or override all the functions of the recipe you are using."
        )

    last_error: Exception = Exception("No valid JWKS found")

    with fetch_lock:
        # check again if the keys are in cache
        # because another thread might have fetched the keys while this one was waiting for the lock
        matching_keys = find_matching_keys_in_cache(kid)
        if matching_keys is not None:
            return matching_keys

        try:
            for path in core_paths:
                if environ.get("SUPERTOKENS_ENV") == "testing":
                    log_debug_message("Attempting to fetch JWKS from path: %s", path)

                cached_jwks: Optional[List[PyJWK]] = None
                try:
                    log_debug_message("Fetching jwk set from the configured uri")
                    with requests.get(
                        path, timeout=JWKSConfig["request_timeout"] / 1000
                    ) as response:  # 5 second timeout
                        response.raise_for_status()
                        cached_jwks = PyJWKSet.from_dict(response.json()).keys  # type: ignore
                except Exception as e:
                    last_error = e

                if cached_jwks is not None:  # we found a valid JWKS
                    with RWLockContext(mutex, read=False):
                        cached_keys = CachedKeys(
                            cached_jwks, config.jwks_refresh_interval_sec
                        )
                    log_debug_message("Returning JWKS from fetch")
                    matching_keys = find_matching_keys(cached_jwks, kid)
                    if matching_keys is not None:
                        return matching_keys

                    raise Exception("No matching JWKS found")
        finally:
            with RWLockContext(mutex, read=False):
                last_fetch_time_ms = get_timestamp_ms()

    raise last_error
