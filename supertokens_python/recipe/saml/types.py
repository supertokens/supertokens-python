# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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
from __future__ import annotations

from typing import Any, Dict, List, Optional

from typing_extensions import Literal


class SAMLClient:
    def __init__(
        self,
        client_id: str,
        redirect_uris: List[str],
        default_redirect_uri: str,
        idp_entity_id: str,
        idp_signing_certificate: Optional[str] = None,
        allow_idp_initiated_login: bool = False,
        enable_request_signing: bool = False,
    ):
        self.client_id = client_id
        self.redirect_uris = redirect_uris
        self.default_redirect_uri = default_redirect_uri
        self.idp_entity_id = idp_entity_id
        self.idp_signing_certificate = idp_signing_certificate
        self.allow_idp_initiated_login = allow_idp_initiated_login
        self.enable_request_signing = enable_request_signing

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "clientId": self.client_id,
            "redirectURIs": self.redirect_uris,
            "defaultRedirectURI": self.default_redirect_uri,
            "idpEntityId": self.idp_entity_id,
            "allowIDPInitiatedLogin": self.allow_idp_initiated_login,
            "enableRequestSigning": self.enable_request_signing,
        }
        if self.idp_signing_certificate is not None:
            result["idpSigningCertificate"] = self.idp_signing_certificate
        return result

    @staticmethod
    def from_json(json: Dict[str, Any]) -> SAMLClient:
        return SAMLClient(
            client_id=json["clientId"],
            redirect_uris=json["redirectURIs"],
            default_redirect_uri=json["defaultRedirectURI"],
            idp_entity_id=json["idpEntityId"],
            idp_signing_certificate=json.get("idpSigningCertificate"),
            allow_idp_initiated_login=json.get("allowIDPInitiatedLogin", False),
            enable_request_signing=json.get("enableRequestSigning", False),
        )


# RecipeInterface response types


class CreateOrUpdateClientOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, client: SAMLClient):
        self.client = client


class CreateOrUpdateClientInvalidMetadataXMLError:
    status: Literal["INVALID_METADATA_XML_ERROR"] = "INVALID_METADATA_XML_ERROR"


class CreateOrUpdateClientDuplicateIdpEntityError:
    status: Literal["DUPLICATE_IDP_ENTITY_ERROR"] = "DUPLICATE_IDP_ENTITY_ERROR"


class ListClientsOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, clients: List[SAMLClient]):
        self.clients = clients


class RemoveClientOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, did_exist: bool):
        self.did_exist = did_exist


class CreateLoginRequestOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, redirect_uri: str):
        self.redirect_uri = redirect_uri


class CreateLoginRequestInvalidClientError:
    status: Literal["INVALID_CLIENT_ERROR"] = "INVALID_CLIENT_ERROR"


class VerifySAMLResponseOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, redirect_uri: str):
        self.redirect_uri = redirect_uri


class VerifySAMLResponseVerificationFailedError:
    status: Literal["SAML_RESPONSE_VERIFICATION_FAILED_ERROR"] = (
        "SAML_RESPONSE_VERIFICATION_FAILED_ERROR"
    )


class VerifySAMLResponseInvalidRelayStateError:
    status: Literal["INVALID_RELAY_STATE_ERROR"] = "INVALID_RELAY_STATE_ERROR"


class VerifySAMLResponseInvalidClientError:
    status: Literal["INVALID_CLIENT_ERROR"] = "INVALID_CLIENT_ERROR"


class VerifySAMLResponseIDPLoginDisallowedError:
    status: Literal["IDP_LOGIN_DISALLOWED_ERROR"] = "IDP_LOGIN_DISALLOWED_ERROR"


class GetUserInfoOkResult:
    status: Literal["OK"] = "OK"

    def __init__(
        self,
        sub: str,
        email: str,
        claims: Dict[str, Any],
    ):
        self.sub = sub
        self.email = email
        self.claims = claims


class GetUserInfoInvalidTokenError:
    status: Literal["INVALID_TOKEN_ERROR"] = "INVALID_TOKEN_ERROR"
