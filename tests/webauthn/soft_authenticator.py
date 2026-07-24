"""
A minimal software WebAuthn authenticator with full control over the signature
counter (signCount).

Real hardware authenticators (Windows Hello, security keys) increment the
counter on every assertion, while Apple/Google passkeys keep it at 0 forever —
which skips the core's clone-detection check (WebAuthn L3 section 7.2 step 24)
entirely. Tests that only ever present signCount = 0 therefore cannot catch
counter-related regressions such as
https://github.com/supertokens/supertokens-core/issues/1195.

Produces `fmt: "none"` attestations, which the core accepts because it verifies
with webauthn4j's non-strict manager.
"""

import base64
import hashlib
import json
import secrets
from typing import Any, Dict, List, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40

CborValue = Union[int, str, bytes, List[Tuple[Any, Any]]]


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def cbor_encode(value: CborValue) -> bytes:
    """
    Minimal CBOR encoder covering only what a "none" attestation needs.
    A list of (key, value) tuples is encoded as a CBOR map — this preserves
    the integer keys that COSE keys require.
    """
    if isinstance(value, bool):
        raise TypeError("booleans not supported")
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, str):
        encoded = value.encode()
        return _cbor_head(3, len(encoded)) + encoded
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, list):
        out = _cbor_head(5, len(value))
        for key, val in value:
            out += cbor_encode(key) + cbor_encode(val)
        return out
    raise TypeError(f"unsupported CBOR value type: {type(value)}")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class SoftAuthenticator:
    """
    One instance == one credential (one P-256 keypair). The `sign_count`
    arguments give tests full control over the counter values reported to the
    Relying Party.
    """

    def __init__(self, *, rp_id: str, origin: str):
        self.rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        self.origin = origin
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public_numbers = self.private_key.public_key().public_numbers()
        self.x = public_numbers.x.to_bytes(32, "big")
        self.y = public_numbers.y.to_bytes(32, "big")
        self.credential_id = secrets.token_bytes(32)

    def create_attestation(
        self, register_options: Dict[str, Any], *, sign_count: int = 0
    ) -> Dict[str, Any]:
        """
        Build a RegistrationPayload for POST /auth/webauthn/signup from a
        response body of POST /auth/webauthn/options/register. `sign_count`
        becomes the initial counter value stored by the RP.
        """
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": register_options["challenge"],
                "origin": self.origin,
                "crossOrigin": False,
            }
        ).encode()

        # COSE_Key: kty(1)=EC2(2), alg(3)=ES256(-7), crv(-1)=P-256(1), x(-2), y(-3)
        cose_key = cbor_encode([(1, 2), (3, -7), (-1, 1), (-2, self.x), (-3, self.y)])

        auth_data = (
            self.rp_id_hash
            + bytes([FLAG_UP | FLAG_UV | FLAG_AT])
            + sign_count.to_bytes(4, "big")
            + bytes(16)  # aaguid (zero = "none")
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + cose_key
        )

        attestation_object = cbor_encode(
            [("fmt", "none"), ("attStmt", []), ("authData", auth_data)]
        )

        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation_object),
                "transports": ["internal"],
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def create_assertion(
        self,
        signin_options: Dict[str, Any],
        *,
        sign_count: int,
        user_handle: str,
    ) -> Dict[str, Any]:
        """
        Build an AuthenticationPayload for POST /auth/webauthn/signin from a
        response body of POST /auth/webauthn/options/signin. `sign_count` is
        the counter value this assertion reports; `user_handle` is
        register_options["user"]["id"] from registration.
        """
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": signin_options["challenge"],
                "origin": self.origin,
                "crossOrigin": False,
            }
        ).encode()

        auth_data = (
            self.rp_id_hash + bytes([FLAG_UP | FLAG_UV]) + sign_count.to_bytes(4, "big")
        )
        signed_over = auth_data + hashlib.sha256(client_data).digest()
        # DER-encoded ECDSA, as WebAuthn ES256 requires
        signature = self.private_key.sign(signed_over, ec.ECDSA(hashes.SHA256()))

        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": user_handle,
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
