from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, List, Literal, Optional, TypeVar, Union

from supertokens_python.recipe.webauthn.types.config import UserContext
from supertokens_python.types import APIResponse

Status = TypeVar("Status")
"""Generic type for use in `APIResponse` subclasses"""


@dataclass
class BaseApiResponse(APIResponse, Generic[Status]):
    """
    Generic response object with a `status` field.
    """

    status: Status


@dataclass
class ErrorReasonApiResponse(BaseApiResponse[Status]):
    """
    Generic error response object with additional `reason` field.
    """

    reason: str


@dataclass
class ErrorErrApiResponse(BaseApiResponse[Status]):
    """
    Generic error response object with additional `err` field.
    """

    err: str


class OkApiResponse(BaseApiResponse[Literal["OK"]]):
    """
    Basic success response object with `status = "OK"`
    """

    status = "OK"


ResidentKey = Literal["required", "preferred", "discouraged"]
UserVerification = Literal["required", "preferred", "discouraged"]
Attestation = Literal["none", "indirect", "direct", "enterprise"]
Transports = Literal["ble", "hybrid", "internal", "nfc", "usb"]


# Base class adds the `status: OK` param
@dataclass
class RegisterOptionsResponse(OkApiResponse):
    # for understanding the response, see https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
    # and https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential

    @dataclass
    class RelyingParty:
        rp_id: str
        name: str

    @dataclass
    class User:
        user_id: str
        name: str  # user email
        display_name: str  # user email

    @dataclass
    class ExcludeCredentials:
        exclude_id: str
        cred_type: Literal["public-key"]
        transports: List[Transports]

    @dataclass
    class PubKeyCredParams:
        # we will default to [-8, -7, -257] as supported algorithms.
        # See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        alg: int
        cred_type: Literal["public-key"]

    @dataclass
    class AuthenticatorSelection:
        require_resident_key: bool
        resident_key: ResidentKey
        user_verification: UserVerification

    webauthn_generated_options_id: str
    created_at: str
    expires_at: str
    rp: RelyingParty
    user: User
    challenge: str
    timeout: int
    exclude_credentials: List[ExcludeCredentials]
    attestation: Attestation
    pub_key_cred_params: List[PubKeyCredParams]
    authenticator_selection: AuthenticatorSelection


RegisterOptionsErrorResponse = Union[
    BaseApiResponse[Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"]],
    ErrorErrApiResponse[Literal["INVALID_EMAIL_ERROR"]],
    BaseApiResponse[Literal["INVALID_OPTIONS_ERROR"]],
]


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
    ) -> Union[RegisterOptionsResponse, RegisterOptionsErrorResponse]: ...
