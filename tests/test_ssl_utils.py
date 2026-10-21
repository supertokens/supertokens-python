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
import asyncio
import json
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator, Iterator

import httpx
import jwt
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jwt.algorithms import RSAAlgorithm
from pytest import MonkeyPatch
from pytest_mock import MockerFixture
from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.querier import Querier
from supertokens_python.recipe.thirdparty.providers.custom import (
    verify_id_token_from_jwks_endpoint_and_get_payload,
)
from supertokens_python.recipe.thirdparty.providers.utils import (
    do_get_request,
    do_post_request,
)
from supertokens_python.ssl_utils import get_ssl_context, reset_ssl_context


@pytest.fixture(autouse=True)
def tls_environment(monkeypatch: MonkeyPatch) -> Iterator[None]:
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    reset_ssl_context()
    yield
    reset_ssl_context()


@pytest.fixture
def certificate(tmp_path: Path) -> Path:
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "localhost.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_suffix(".key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


@pytest.fixture
async def tls_server(certificate: Path) -> AsyncIterator[int]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, certificate.with_suffix(".key"))

    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(respond, "127.0.0.1", 0, ssl=context)
    async with server:
        yield server.sockets[0].getsockname()[1]


def test_context_reuse_and_reset(mocker: MockerFixture):
    factory = mocker.spy(httpx, "create_ssl_context")
    context = get_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert get_ssl_context() is context
    factory.assert_called_once_with(verify=True, trust_env=True)
    reset_ssl_context()
    assert get_ssl_context() is not context
    assert factory.call_count == 2


def test_concurrent_initialization():
    # lru_cache allows duplicate cold builds, but only retains one context.
    def load_context(_: int) -> ssl.SSLContext:
        return get_ssl_context()

    with ThreadPoolExecutor(max_workers=4) as executor:
        contexts = list(executor.map(load_context, range(8)))
        assert all(
            c.check_hostname and c.verify_mode == ssl.CERT_REQUIRED for c in contexts
        )
        cached = get_ssl_context()
        assert all(c is cached for c in executor.map(load_context, range(8)))


def test_certificate_environment(
    monkeypatch: MonkeyPatch, certificate: Path, tmp_path: Path, mocker: MockerFixture
):
    default = get_ssl_context()
    factory = mocker.spy(ssl, "create_default_context")
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    from_file = get_ssl_context()
    assert from_file is not default
    assert from_file.cert_store_stats()["x509_ca"] == 1
    factory.assert_called_once_with(cafile=str(certificate))

    # SSL_CERT_FILE takes precedence while SSL_CERT_DIR is also set.
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    get_ssl_context()
    factory.assert_called_with(cafile=str(certificate))
    monkeypatch.delenv("SSL_CERT_FILE")
    from_directory = get_ssl_context()
    factory.assert_called_with(capath=str(tmp_path))
    assert from_directory is not from_file

    monkeypatch.delenv("SSL_CERT_DIR")
    assert get_ssl_context().cert_store_stats()["x509_ca"] > 1


def test_invalid_bundle_does_not_reuse_previous_context(
    monkeypatch: MonkeyPatch, tmp_path: Path
):
    get_ssl_context()
    path = tmp_path / "invalid.pem"
    monkeypatch.setenv("SSL_CERT_FILE", str(path))
    with pytest.raises(OSError):
        get_ssl_context()
    path.write_text("not a certificate")
    with pytest.raises(ssl.SSLError):
        get_ssl_context()


def test_keylog_environment(monkeypatch: MonkeyPatch, tmp_path: Path):
    previous = get_ssl_context()
    log_path = tmp_path / "tls.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(log_path))
    context = get_ssl_context()
    assert context is not previous
    assert context.keylog_filename == str(log_path)
    monkeypatch.delenv("SSLKEYLOGFILE")
    assert get_ssl_context().keylog_filename is None


async def test_https_verification(
    monkeypatch: MonkeyPatch, certificate: Path, tls_server: int
):
    url = f"https://localhost:{tls_server}"
    with pytest.raises(httpx.ConnectError):
        await do_get_request(url)
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    assert await do_get_request(url) == {}
    assert await do_get_request(url) == {}
    with pytest.raises(httpx.ConnectError):
        await do_get_request(f"https://127.0.0.1:{tls_server}")


async def test_core_and_provider_requests_share_tls_configuration(
    mocker: MockerFixture,
):
    factory = mocker.spy(ssl, "create_default_context")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({"sub": "user", "aud": "client"}, key, algorithm="RS256")
    public_key = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    with respx.mock as router:
        router.get("http://localhost/core").respond(200, json={})
        router.get("https://localhost/userinfo").respond(200, json={"sub": "user"})
        router.post("https://localhost/token").respond(
            200, json={"access_token": "token"}
        )
        router.get("https://localhost/jwks").respond(200, json={"keys": [public_key]})
        querier = Querier([])
        for _ in range(2):
            assert (
                await querier.api_request("http://localhost/core", "GET", 1)
            ).status_code == 200
            assert await do_get_request("https://localhost/userinfo") == {"sub": "user"}
            assert await do_post_request(
                "https://localhost/token", {"code": "code"}
            ) == (200, {"access_token": "token"})
            payload = await verify_id_token_from_jwks_endpoint_and_get_payload(
                token, "https://localhost/jwks", "client"
            )
            assert payload["sub"] == "user"
        assert factory.call_count == 1


def test_sync_calls_and_separate_event_loops():
    context = get_ssl_context()
    with respx.mock as router:
        router.get("https://localhost/userinfo").respond(200, json={})
        try:
            for _ in range(2):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    assert sync(do_get_request("https://localhost/userinfo")) == {}
                    assert sync(do_get_request("https://localhost/userinfo")) == {}
                    assert get_ssl_context() is context
                finally:
                    loop.close()
        finally:
            asyncio.set_event_loop(None)
