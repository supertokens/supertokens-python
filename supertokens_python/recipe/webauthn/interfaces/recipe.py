from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal, Optional

from supertokens_python.recipe.webauthn.types.config import UserContext
from supertokens_python.types import APIResponse


class OkApiResponse(APIResponse):
    status = "OK"


class ErrorApiResponse(APIResponse):
    pass


class ErrorReasonApiResponse(ErrorApiResponse):
    reason: str


ResidentKey = Literal["required", "preferred", "discouraged"]
UserVerification = Literal["required", "preferred", "discouraged"]
Attestation = Literal["none", "indirect", "direct", "enterprise"]
Transports = Literal["ble", "hybrid", "internal", "nfc", "usb"]


class RegisterOptionsResponse(OkApiResponse):
    webauthn_generated_options_id: str
    created_at: str
    expires_at: str
    # TODO: Port types to TypedDicts?
    # # for understanding the response, see https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential and https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
    # rp: {
    #     id: str
    #     name: str
    # }
    # user: {
    #     id: str
    #     name: str # user email
    #     display_name: str #user email
    # }
    # challenge: str
    # timeout: int
    # exclude_credentials: {
    #     id: str
    #     type: Literal["public-key"]
    #     transports: list[Transports]
    # }[]
    # attestation: Attestation
    # pubKeyCredParams: {
    #     # we will default to [-8, -7, -257] as supported algorithms. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    #     alg: Literal[-8, -7, -257]
    #     type: Literal["public-key"]
    # }[]
    # authenticatorSelection: {
    #     requireResidentKey: bool
    #     residentKey: ResidentKey
    #     userVerification: UserVerification
    # }


class RecipeInterface(ABC):
    # TODO: How do you implement this mutually-exclusive function param?
    # & ( | { recoverAccountToken: str } | { displayName: str | undefined email: str } )

    @abstractmethod
    async def register_options(
        self,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        resident_key: Optional[ResidentKey],
        user_verification: Optional[UserVerification],
        attestation: Optional[Attestation],
        supportedAlgorithmIds: Optional[list[int]],
        timeout: Optional[int],
        tenantId: str,
        userContext: UserContext,
    ): ...
