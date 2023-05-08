import json
import urllib.request
from typing import List, Optional
from urllib.error import URLError

from jwt import PyJWK, PyJWKSet
from jwt.api_jwt import decode_complete as decode_token  # type: ignore

from supertokens_python.utils import get_timestamp_ms

from .constants import JWKCacheMaxAgeInMs, JWKRequestCooldownInMs


class JWKClient:
    def __init__(
        self,
        uri: str,
        cooldown_duration: int = JWKRequestCooldownInMs,
        cache_max_age: int = JWKCacheMaxAgeInMs,
    ):
        """A client for retrieving JSON Web Key Sets (JWKS) from a given URI.

        Args:
            uri (str): The URI of the JWKS.
            cooldown_duration (int, optional): The cooldown duration in ms. Defaults to 500 seconds.
            cache_max_age (int, optional): The cache max age in ms. Defaults to 5 minutes.

        Note: The JSON Web Key Set is fetched when no key matches the selection
        process but only as frequently as the `self.cooldown_duration` option
        allows to prevent abuse. The `self.cache_max_age` option is used to
        determine how long the JWKS is cached for.

        Whenever you make a call to `get_signing_key_from_jwt`, the JWKS
        is fetched if it is older than `self.cache_max_age` ms unless
        cooldown is active.
        """
        self.uri = uri
        self.cooldown_duration = cooldown_duration
        self.cache_max_age = cache_max_age
        self.timeout_sec = 5
        self.last_fetch_time: int = 0
        self.jwk_set: Optional[PyJWKSet] = None

    def reload(self):
        try:
            with urllib.request.urlopen(self.uri, timeout=self.timeout_sec) as response:
                self.jwk_set = PyJWKSet.from_dict(json.load(response))  # type: ignore
                self.last_fetch_time = get_timestamp_ms()
        except URLError:
            raise JWKSRequestError("Failed to fetch jwk set from the configured uri")

    def is_cooling_down(self) -> bool:
        return (self.last_fetch_time > 0) and (
            get_timestamp_ms() - self.last_fetch_time < self.cooldown_duration
        )

    def is_fresh(self) -> bool:
        return (self.last_fetch_time > 0) and (
            get_timestamp_ms() - self.last_fetch_time < self.cache_max_age
        )

    def get_latest_keys(self) -> List[PyJWK]:
        if self.jwk_set is None or not self.is_fresh():
            self.reload()

        if self.jwk_set is None:
            raise JWKSRequestError("Failed to fetch the latest keys")

        all_keys: List[PyJWK] = self.jwk_set.keys  # type: ignore

        return all_keys

    def get_matching_key_from_jwt(self, token: str) -> PyJWK:
        header = decode_token(token, options={"verify_signature": False})["header"]
        kid: str = header["kid"]  # type: ignore

        if self.jwk_set is None or not self.is_fresh():
            self.reload()

        assert self.jwk_set is not None

        try:
            return self.jwk_set[kid]  # type: ignore
        except KeyError:
            if not self.is_cooling_down():
                # One more attempt to fetch the latest keys
                # and then try to find the key again.
                self.reload()
                try:
                    return self.jwk_set[kid]  # type: ignore
                except KeyError:
                    pass
        except Exception:
            raise JWKSKeyNotFoundError("No key found for the given kid")

        raise JWKSKeyNotFoundError("No key found for the given kid")


class JWKSKeyNotFoundError(Exception):
    pass


class JWKSRequestError(Exception):
    pass
