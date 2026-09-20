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
"""Internal TLS configuration shared by short-lived HTTP clients."""

from functools import lru_cache
from os import environ
from ssl import SSLContext
from typing import Optional

import httpx


@lru_cache(maxsize=1)
def _create_ssl_context(
    ssl_cert_file: Optional[str],
    ssl_cert_dir: Optional[str],
    ssl_key_log_file: Optional[str],
) -> SSLContext:
    # Arguments form the cache key; HTTPX reads the environment itself so its
    # certificate selection and TLS defaults remain authoritative.
    return httpx.create_ssl_context(verify=True, trust_env=True)


def get_ssl_context() -> SSLContext:
    """Reuse TLS configuration without sharing clients across event loops.

    Environment changes invalidate the single-entry cache. Changes to certificate
    files at the same path require a process restart or an explicit cache reset.
    Concurrent cold calls may each build a context; subsequent calls reuse the
    cached result. Clients must not modify the context's verification settings.
    """
    return _create_ssl_context(
        environ.get("SSL_CERT_FILE"),
        environ.get("SSL_CERT_DIR"),
        environ.get("SSLKEYLOGFILE"),
    )


def reset_ssl_context() -> None:
    """Clear cached TLS configuration when resetting SDK state in tests."""
    _create_ssl_context.cache_clear()
