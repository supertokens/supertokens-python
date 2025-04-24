from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, List, Literal, Optional, Protocol, TypeVar, Union

from dataclasses_json import LetterCase, dataclass_json

from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.types import APIResponse

Status = TypeVar("Status", bound=str)
"""
Generic type for use in `APIResponse` subclasses.

Constrained to be a subtype of string.
"""


# TODO: Move to supertokens_python types
class HasStatus(Protocol, Generic[Status]):
    status: Status


class HasErr(Protocol, Generic[Status]):
    err: Status


class HasReason(Protocol, Generic[Status]):
    reason: Status


@dataclass_json
@dataclass
class StatusResponse(APIResponse, HasStatus[Status]):
    """
    Generic response object with a `status` field.
    """

    status: Status


@dataclass_json
@dataclass
class StatusReasonResponse(StatusResponse[Status]):
    """
    Generic error response object with `status` and `reason` fields.
    """

    reason: str


@dataclass_json
@dataclass
class StatusErrResponse(StatusResponse[Status]):
    """
    Generic error response object with `status` and `err` fields.
    """

    err: str


class OkResponse(HasStatus[Literal["OK"]]):
    """
    Basic success response object with `status = "OK"`
    """

    status: Literal["OK"] = "OK"


ResidentKey = Literal["required", "preferred", "discouraged"]
UserVerification = Literal["required", "preferred", "discouraged"]
Attestation = Literal["none", "indirect", "direct", "enterprise"]
Transports = Literal["ble", "hybrid", "internal", "nfc", "usb"]


# Base class adds the `status: OK` param
@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the enum
@dataclass
class RegisterOptionsResponse(OkResponse):
    # for understanding the response, see https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
    # and https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the enum
    @dataclass
    class RelyingParty:
        id: str
        name: str

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the enum
    @dataclass
    class User:
        id: str
        name: str  # user email
        display_name: str  # user email

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the enum
    @dataclass
    class ExcludeCredentials:
        id: str
        type: Literal["public-key"]
        transports: List[Transports]

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the enum
    @dataclass
    class PubKeyCredParams:
        # we will default to [-8, -7, -257] as supported algorithms.
        # See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        alg: int
        cred_type: Literal["public-key"]

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the enum
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


# # TODO: Will we ever initialize these objects? Or type-check based on these?
# # If not, we can get away with just typing it, and not actually defining these subclasses
# @dataclass_json
# @dataclass
# class RecoverAccountTokenInvalidErrorResponse(
#     StatusResponse[Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"]]
# ):
#     status: Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"] = "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"


# @dataclass_json
# @dataclass
# class InvalidEmailErrorResponse(StatusErrResponse[Literal["INVALID_EMAIL_ERROR"]]):
#     status: Literal["INVALID_EMAIL_ERROR"] = "INVALID_EMAIL_ERROR"


# @dataclass_json
# @dataclass
# class InvalidOptionsErrorResponse(StatusResponse[Literal["INVALID_OPTIONS_ERROR"]]):
#     status:Literal["INVALID_OPTIONS_ERROR"] = "INVALID_OPTIONS_ERROR"


RegisterOptionsErrorResponse = Union[
    StatusResponse[Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"]],
    # RecoverAccountTokenInvalidErrorResponse,
    StatusErrResponse[Literal["INVALID_EMAIL_ERROR"]],
    # InvalidEmailErrorResponse,
    StatusResponse[Literal["INVALID_OPTIONS_ERROR"]],
    # InvalidOptionsErrorResponse,
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
        supportedAlgorithmIds: Optional[List[int]],
        timeout: Optional[int],
        tenantId: str,
        userContext: UserContext,
    ) -> Union[RegisterOptionsResponse, RegisterOptionsErrorResponse]: ...
