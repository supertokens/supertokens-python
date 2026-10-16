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
A minimal software WebAuthn authenticator for tests.

It produces `fmt: "none"` attestations and ES256 assertions for a single
P-256 credential, which is enough for the core to register the credential
and verify sign ins with it.
"""

import json
import os
from base64 import urlsafe_b64encode
from hashlib import sha256
from typing import Any, Dict, List, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CborValue = Union[int, str, bytes, List[Tuple[Any, Any]]]

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def _cbor_encode(value: CborValue) -> bytes:
    # A list of (key, value) pairs is encoded as a map, so that integer keys
    # (used by COSE keys) keep their order.
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, str):
        utf8 = value.encode("utf-8")
        return _cbor_head(3, len(utf8)) + utf8
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    parts = [_cbor_head(5, len(value))]
    for k, v in value:
        parts.append(_cbor_encode(k))
        parts.append(_cbor_encode(v))
    return b"".join(parts)


def _b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


class SoftAuthenticator:
    def __init__(self, *, rp_id: str, origin: str):
        self.rp_id = rp_id
        self.origin = origin
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = self._private_key.public_key().public_numbers()
        self._x = numbers.x.to_bytes(32, "big")
        self._y = numbers.y.to_bytes(32, "big")
        self.credential_id_bytes = os.urandom(32)
        self.credential_id = _b64url(self.credential_id_bytes)
        self._rp_id_hash = sha256(rp_id.encode("utf-8")).digest()
        # COSE_Key: kty(1)=EC2(2), alg(3)=ES256(-7), crv(-1)=P-256(1), x(-2), y(-3)
        self._cose_key = _cbor_encode(
            [(1, 2), (3, -7), (-1, 1), (-2, self._x), (-3, self._y)]
        )

    def _client_data_json(self, type_: str, challenge: str) -> bytes:
        return json.dumps(
            {
                "type": type_,
                "challenge": challenge,
                "origin": self.origin,
                "crossOrigin": False,
            }
        ).encode("utf-8")

    def create_attestation(
        self, register_options: Dict[str, Any], sign_count: int = 0
    ) -> Dict[str, Any]:
        """Returns a registration payload for the given register options response."""
        client_data_json = self._client_data_json(
            "webauthn.create", register_options["challenge"]
        )
        attested_credential_data = (
            bytes(16)  # aaguid
            + len(self.credential_id_bytes).to_bytes(2, "big")
            + self.credential_id_bytes
            + self._cose_key
        )
        auth_data = (
            self._rp_id_hash
            + bytes([FLAG_UP | FLAG_UV | FLAG_AT])
            + sign_count.to_bytes(4, "big")
            + attested_credential_data
        )
        attestation_object = _cbor_encode(
            [("fmt", "none"), ("attStmt", []), ("authData", auth_data)]
        )
        return {
            "id": self.credential_id,
            "rawId": self.credential_id,
            "response": {
                "clientDataJSON": _b64url(client_data_json),
                "attestationObject": _b64url(attestation_object),
                "transports": ["internal"],
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def create_assertion(
        self, sign_in_options: Dict[str, Any], user_handle: str, sign_count: int = 0
    ) -> Dict[str, Any]:
        """Returns an authentication payload for the given sign in options response."""
        client_data_json = self._client_data_json(
            "webauthn.get", sign_in_options["challenge"]
        )
        authenticator_data = (
            self._rp_id_hash
            + bytes([FLAG_UP | FLAG_UV])
            + sign_count.to_bytes(4, "big")
        )
        signature = self._private_key.sign(
            authenticator_data + sha256(client_data_json).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": self.credential_id,
            "rawId": self.credential_id,
            "response": {
                "clientDataJSON": _b64url(client_data_json),
                "authenticatorData": _b64url(authenticator_data),
                "signature": _b64url(signature),
                "userHandle": user_handle,
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
