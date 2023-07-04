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
from json import dumps, loads
from typing import Any, Dict, Optional

from supertokens_python.utils import utf_base64decode, utf_base64encode

# why separators is used in dumps:
# - without it's use, output of dumps is: '{"alg": "RS256", "typ": "JWT", "version": "1"}'
# - with it's use, output of dumps is: '{"alg":"RS256","typ":"JWT","version":"1"}'
# we require the non-spaced version, else the base64 encoding string will end up different than required
_allowed_headers = [
    utf_base64encode(
        dumps(
            {"alg": "RS256", "typ": "JWT", "version": "2"},
            separators=(",", ":"),
            sort_keys=True,
        ),
        urlsafe=False,
    )
]


class ParsedJWTInfo:
    def __init__(
        self,
        version: int,
        raw_token_string: str,
        raw_payload: str,
        header: str,
        payload: Dict[str, Any],
        signature: str,
        kid: Optional[str],
        parsed_header: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.version = version
        self.raw_token_string = raw_token_string
        self.raw_payload = raw_payload
        self.header = header
        self.payload = payload
        self.signature = signature
        self.kid = kid
        self.parsed_header = parsed_header


def parse_jwt_without_signature_verification(jwt: str) -> ParsedJWTInfo:
    splitted_input = jwt.split(".")
    LATEST_TOKEN_VERSION = 3
    if len(splitted_input) != 3:
        raise Exception("invalid jwt")

    # V1 and V2 are functionally identical, plus all legacy tokens should be V2 now.
    # So we can assume these defaults:
    version = 2
    kid = None
    parsed_header = None
    # V2 or older tokens didn't save the key id
    header, payload, signature = splitted_input
    # checking the header
    if header not in _allowed_headers:
        parsed_header = loads(utf_base64decode(header, True))
        header_version = parsed_header.get("version", str(LATEST_TOKEN_VERSION))

        try:
            version = int(header_version)
        except ValueError:
            version = None

        kid = parsed_header.get("kid")
        # isinstance(version, int) returns False for None (if it fails to parse the version)
        if (
            parsed_header["typ"] != "JWT"
            or not isinstance(version, int)
            or version < 3
            or kid is None
        ):
            raise Exception("JWT header mismatch")

    return ParsedJWTInfo(
        version=version,
        raw_token_string=jwt,
        raw_payload=payload,
        header=header,
        # Ideally we would only parse this after the signature verification is done
        # We do this at the start, since we want to check if a token can be a supertokens access token or not.
        payload=loads(utf_base64decode(payload, True)),
        signature=signature,
        kid=kid,
        parsed_header=parsed_header,
    )
