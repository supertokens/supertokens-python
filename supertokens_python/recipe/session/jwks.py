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

import requests
from os import environ
from typing import List, Optional
from typing_extensions import TypedDict

from jwt import PyJWK, PyJWKSet

from .constants import JWKCacheMaxAgeInMs

from supertokens_python.utils import RWMutex, RWLockContext, get_timestamp_ms
from supertokens_python.querier import Querier
from supertokens_python.logger import log_debug_message


class JWKSConfigType(TypedDict):
    cache_max_age: int
    request_timeout: int


JWKSConfig: JWKSConfigType = {
    "cache_max_age": JWKCacheMaxAgeInMs,
    "request_timeout": 10000,  # 10s
}


class CachedKeys:
    def __init__(self, keys: List[PyJWK]):
        self.keys = keys
        self.last_refresh_time = get_timestamp_ms()

    def is_fresh(self):
        return get_timestamp_ms() - self.last_refresh_time < JWKSConfig["cache_max_age"]


cached_keys: Optional[CachedKeys] = None
mutex = RWMutex()

# only for testing purposes
def reset_jwks_cache():
    with RWLockContext(mutex, read=False):
        global cached_keys
        cached_keys = None


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


def get_latest_keys(kid: Optional[str] = None) -> List[PyJWK]:
    global cached_keys

    if environ.get("SUPERTOKENS_ENV") == "testing":
        log_debug_message("Called find_jwk_client")

    with RWLockContext(mutex, read=True):
        matching_keys = find_matching_keys(get_cached_keys(), kid)
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

    with RWLockContext(mutex, read=False):
        # check again if the keys are in cache
        # because another thread might have fetched the keys while this one was waiting for the lock
        matching_keys = find_matching_keys(get_cached_keys(), kid)
        if matching_keys is not None:
            return matching_keys

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
                cached_keys = CachedKeys(cached_jwks)
                log_debug_message("Returning JWKS from fetch")
                matching_keys = find_matching_keys(get_cached_keys(), kid)
                if matching_keys is not None:
                    return matching_keys

                raise Exception("No matching JWKS found")

    raise last_error
