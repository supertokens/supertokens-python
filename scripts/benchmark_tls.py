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
"""Compare TLS/client reuse: python scripts/benchmark_tls.py after make dev-install.

Uses local HTTP/HTTPS servers and temporary certificates. Each variant performs
one cold request followed by 60 warm requests, with real HTTPX transports.
"""

import asyncio
import json
import os
import platform
import ssl
import statistics
import tempfile
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import List, Optional, Union
from unittest.mock import patch

import certifi
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from supertokens_python.ssl_utils import get_ssl_context, reset_ssl_context


async def main() -> None:
    print(
        json.dumps(
            {
                "python": platform.python_version(),
                "httpx": httpx.__version__,
                "openssl": ssl.OPENSSL_VERSION,
                "os": platform.platform(),
                "requests_per_variant": 61,
                "concurrency": 1,
                "trust": "certifi bundle plus ephemeral local CA",
            }
        )
    )
    with tempfile.TemporaryDirectory() as directory:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]
                ),
                False,
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        cert_path = Path(directory) / "server.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path = Path(directory) / "server.key"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        bundle = Path(directory) / "ca.pem"
        bundle.write_bytes(Path(certifi.where()).read_bytes() + cert_path.read_bytes())
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        connections = 0

        async def serve(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            nonlocal connections
            connections += 1
            try:
                while True:
                    await reader.readuntil(b"\r\n\r\n")
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}"
                    )
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        with patch.dict(
            os.environ,
            {"SSL_CERT_FILE": str(bundle), "NO_PROXY": "localhost,127.0.0.1"},
        ):
            for scheme in ("http", "https"):
                server = await asyncio.start_server(
                    serve,
                    "127.0.0.1",
                    0,
                    ssl=server_context if scheme == "https" else None,
                )
                url = f"{scheme}://127.0.0.1:{server.sockets[0].getsockname()[1]}/"
                async with server:
                    for variant in ("fresh", "cached-context", "shared-client"):
                        reset_ssl_context()
                        connections = 0
                        contexts = 0
                        context_ms = 0.0
                        original = ssl.create_default_context

                        def counted(
                            purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
                            *,
                            cafile: Optional[str] = None,
                            capath: Optional[str] = None,
                            cadata: Optional[Union[str, bytes]] = None,
                        ) -> ssl.SSLContext:
                            nonlocal contexts, context_ms
                            started = time.perf_counter()
                            result = original(
                                purpose, cafile=cafile, capath=capath, cadata=cadata
                            )
                            contexts += 1
                            context_ms += (time.perf_counter() - started) * 1000
                            return result

                        elapsed: List[float] = []
                        initialization: List[float] = []
                        context: Optional[ssl.SSLContext] = None
                        shared: Optional[httpx.AsyncClient] = None
                        with patch("ssl.create_default_context", counted):
                            for _ in range(61):
                                started = time.perf_counter()
                                if variant == "cached-context":
                                    context = get_ssl_context()
                                client = shared or httpx.AsyncClient(
                                    timeout=30.0,
                                    verify=context if context is not None else True,
                                )
                                initialization.append(
                                    (time.perf_counter() - started) * 1000
                                )
                                if variant == "shared-client":
                                    shared = client
                                try:
                                    response = await client.get(url)
                                    assert response.json() == {}
                                finally:
                                    if shared is None:
                                        await client.aclose()
                                elapsed.append((time.perf_counter() - started) * 1000)
                            if shared is not None:
                                await shared.aclose()
                        warm = sorted(elapsed[1:])
                        print(
                            json.dumps(
                                {
                                    "scheme": scheme,
                                    "variant": variant,
                                    "cold_ms": round(elapsed[0], 3),
                                    "warm_median_ms": round(statistics.median(warm), 3),
                                    "warm_p95_ms": round(
                                        warm[int(len(warm) * 0.95) - 1], 3
                                    ),
                                    "warm_init_median_ms": round(
                                        statistics.median(initialization[1:]), 3
                                    ),
                                    "contexts": contexts,
                                    "context_total_ms": round(context_ms, 3),
                                    "connections": connections,
                                    "tls_handshakes": connections
                                    if scheme == "https"
                                    else 0,
                                }
                            )
                        )


if __name__ == "__main__":
    asyncio.run(main())
