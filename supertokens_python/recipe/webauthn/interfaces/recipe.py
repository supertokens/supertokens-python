from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    Generic,
    List,
    Literal,
    Optional,
    Protocol,
    TypedDict,
    TypeVar,
    Union,
)

from dataclasses_json import LetterCase, dataclass_json

from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.types import APIResponse, RecipeUserId, User

Status = TypeVar("Status", bound=str)
Reason = TypeVar("Reason", bound=str)

Base64URLString = str
COSEAlgorithmIdentifier = int


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
class StatusReasonResponse(StatusResponse[Status], Generic[Status, Reason]):
    """
    Generic error response object with `status` and `reason` fields.
    """

    reason: Reason


@dataclass_json
@dataclass
class StatusErrResponse(StatusResponse[Status]):
    """
    Generic error response object with `status` and `err` fields.
    """

    err: str


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class OkResponse(HasStatus[Literal["OK"]]):
    """
    Basic success response object with `status = "OK"`
    """

    status: Literal["OK"]


ResidentKey = Literal["required", "preferred", "discouraged"]
UserVerification = Literal["required", "preferred", "discouraged"]
Attestation = Literal["none", "indirect", "direct", "enterprise"]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class CredentialPayloadBase:
    id: str
    rawId: str
    authenticatorAttachment: Optional[Literal["platform", "cross-platform"]]
    clientExtensionResults: Dict[str, Any]
    type: Literal["public-key"]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class AuthenticatorAssertionResponseJSON:
    clientDataJSON: Base64URLString
    authenticatorData: Base64URLString
    signature: Base64URLString
    userHandle: Optional[Base64URLString]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class AuthenticationPayload(CredentialPayloadBase):
    response: AuthenticatorAssertionResponseJSON


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class AuthenticatorAttestationResponseJSON:
    clientDataJSON: Base64URLString
    attestationObject: Base64URLString
    authenticatorData: Optional[Base64URLString]
    transports: Optional[
        List[Literal["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]]
    ]
    publicKeyAlgorithm: Optional[COSEAlgorithmIdentifier]
    publicKey: Optional[Base64URLString]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class RegistrationPayload(CredentialPayloadBase):
    response: AuthenticatorAttestationResponseJSON


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class CredentialPayload(CredentialPayloadBase):
    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
    @dataclass
    class Response:
        client_data_json: str
        attestation_object: str
        transports: Optional[
            List[
                Literal[
                    "ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"
                ]
            ]
        ]
        user_handle: str

    response: Response


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class RegisterOptionsResponse(OkResponse):
    # for understanding the response, see https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
    # and https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
    @dataclass
    class RelyingParty:
        id: str
        name: str

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
    @dataclass
    class User:
        id: str
        name: str  # user email
        display_name: str  # user email

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
    @dataclass
    class ExcludeCredentials:
        id: str
        transports: List[Literal["ble", "hybrid", "internal", "nfc", "usb"]]
        type: Literal["public-key"] = "public-key"

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
    @dataclass
    class PubKeyCredParams:
        # we will default to [-8, -7, -257] as supported algorithms.
        # See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        alg: int
        type: Literal["public-key"] = "public-key"

    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
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
    StatusResponse[
        Literal[
            "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR",
            "INVALID_OPTIONS_ERROR",
        ]
    ],
    StatusErrResponse[Literal["INVALID_EMAIL_ERROR"]],
]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class SignInOptionsResponse(OkResponse):
    webauthn_generated_options_id: str
    created_at: str
    expires_at: str
    challenge: str
    timeout: int
    user_verification: UserVerification


SignInOptionsErrorResponse = StatusResponse[Literal["INVALID_OPTIONS_ERROR"]]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class CreateNewRecipeUserResponse(OkResponse):
    user: User
    recipe_user_id: RecipeUserId


CreateNewRecipeUserErrorResponse = Union[
    StatusResponse[
        Literal[
            "EMAIL_ALREADY_EXISTS_ERROR",
            "OPTIONS_NOT_FOUND_ERROR",
            "INVALID_OPTIONS_ERROR",
            "INVALID_CREDENTIALS_ERROR",
        ]
    ],
    StatusReasonResponse[Literal["INVALID_AUTHENTICATOR_ERROR"], str],
]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class SignUpReponse(OkResponse):
    user: User
    recipe_user_id: RecipeUserId


SignUpErrorResponse = Union[
    CreateNewRecipeUserErrorResponse,
    StatusReasonResponse[
        Literal["LINKING_TO_SESSION_USER_FAILED"],
        Literal[
            "EMAIL_VERIFICATION_REQUIRED",
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
            "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
        ],
    ],
]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class VerifyCredentialsResponse(OkResponse):
    user: User
    recipe_user_id: RecipeUserId


VerifyCredentialsErrorResponse = StatusResponse[
    Literal[
        "INVALID_CREDENTIALS_ERROR",
        "INVALID_OPTIONS_ERROR",
        "INVALID_AUTHENTICATOR_ERROR",
        "CREDENTIAL_NOT_FOUND_ERROR",
        "UNKNOWN_USER_ID_ERROR",
        "OPTIONS_NOT_FOUND_ERROR",
    ]
]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class SignInResponse(OkResponse):
    user: User
    recipe_user_id: RecipeUserId


SignInErrorResponse = Union[
    VerifyCredentialsErrorResponse,
    StatusReasonResponse[
        Literal["LINKING_TO_SESSION_USER_FAILED"],
        Literal[
            "EMAIL_VERIFICATION_REQUIRED",
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
            "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
        ],
    ],
]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class GenerateRecoverAccountTokenResponse(OkResponse):
    token: str


GenerateRecoverAccountTokenErrorResponse = StatusResponse[
    Literal["UNKNOWN_USER_ID_ERROR"]
]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class ConsumeRecoverAccountTokenResponse(OkResponse):
    email: str
    user_id: str


ConsumeRecoverAccountTokenErrorResponse = StatusResponse[
    Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"]
]


RegisterCredentialErrorResponse = Union[
    StatusResponse[
        Literal[
            "INVALID_CREDENTIALS_ERROR",
            "OPTIONS_NOT_FOUND_ERROR",
            "INVALID_OPTIONS_ERROR",
        ]
    ],
    StatusReasonResponse[Literal["INVALID_AUTHENTICATOR_ERROR"], str],
]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class GetUserFromRecoverAccountTokenResponse(OkResponse):
    user: User
    recipe_user_id: RecipeUserId


GetUserFromRecoverAccountTokenErrorResponse = StatusResponse[
    Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"]
]

RemoveCredentialErrorResponse = StatusResponse[Literal["CREDENTIAL_NOT_FOUND_ERROR"]]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class GetCredentialResponse(OkResponse):
    webauthn_credential_id: str
    relying_party_id: str
    recipe_user_id: RecipeUserId
    created_at: int


GetCredentialErrorResponse = StatusResponse[Literal["CREDENTIAL_NOT_FOUND_ERROR"]]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class ListCredentialsResponse(OkResponse):
    @dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
    @dataclass
    class Credential:
        webauthn_credential_id: str
        relying_party_id: str
        recipe_user_id: str
        created_at: int

    credentials: List[Credential]


RemoveGeneratedOptionsErrorResponse = StatusResponse[Literal["OPTIONS_NOT_FOUND_ERROR"]]


@dataclass_json(letter_case=LetterCase.CAMEL)  # type: ignore - Type Errors in the library enum
@dataclass
class GetGeneratedOptionsResponse(OkResponse):
    webauthn_generated_options_id: str
    relying_party_id: str
    relying_party_name: str
    user_verification: UserVerification
    user_presence: bool
    origin: str
    email: str
    timeout: str
    challenge: str
    created_at: int
    expires_at: int


GetGeneratedOptionsErrorResponse = StatusResponse[Literal["OPTIONS_NOT_FOUND_ERROR"]]

UpdateUserEmailErrorResponse = StatusResponse[
    Literal["EMAIL_ALREADY_EXISTS_ERROR", "UNKNOWN_USER_ID_ERROR"]
]


class RecipeInterface(ABC):
    class _RecoverAccountTokenInput(TypedDict):
        recover_account_token: str

    class _DisplayNameEmailInput(TypedDict):
        display_name: Optional[str]
        email: str

    @abstractmethod
    async def register_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        resident_key: Optional[ResidentKey],
        user_verification: Optional[UserVerification],
        user_presence: Optional[bool],
        attestation: Optional[Attestation],
        supported_algorithm_ids: Optional[List[int]],
        timeout: Optional[int],
        tenant_id: str,
        user_context: UserContext,
        **kwargs: Union[_RecoverAccountTokenInput, _DisplayNameEmailInput],
    ) -> Union[RegisterOptionsResponse, RegisterOptionsErrorResponse]: ...

    @abstractmethod
    async def sign_in_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        user_presence: Optional[bool],
        timeout: Optional[int],
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[SignInOptionsResponse, SignInOptionsErrorResponse]: ...

    @abstractmethod
    async def sign_up(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Optional[bool],
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[SignUpReponse, SignUpErrorResponse]: ...

    @abstractmethod
    async def sign_in(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: AuthenticationPayload,
        session: Optional[SessionContainer],
        shouldTryLinkingWithSessionUser: Optional[bool],
        tenantId: str,
        userContext: UserContext,
    ) -> Union[SignInResponse, SignInErrorResponse]: ...

    @abstractmethod
    async def verify_credentials(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: AuthenticationPayload,
        tenantId: str,
        userContext: UserContext,
    ) -> Union[VerifyCredentialsResponse, VerifyCredentialsErrorResponse]: ...

    @abstractmethod
    async def create_new_recipe_user(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[CreateNewRecipeUserResponse, CreateNewRecipeUserErrorResponse]:
        """
        This function is meant only for creating the recipe in the core and nothing else.
        We added this even though signUp exists cause devs may override signup expecting it
        to be called just during sign up. But we also need a version of signing up which can be
        called during operations like creating a user during account recovery flow.
        """
        ...

    @abstractmethod
    async def generate_recover_account_token(
        self,
        *,
        user_id: str,
        email: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[
        GenerateRecoverAccountTokenResponse,
        GenerateRecoverAccountTokenErrorResponse,
    ]:
        """
        We pass in the email as well to this function cause the input userId
        may not be associated with an webauthn account. In this case, we
        need to know which email to use to create an webauthn account later on.
        """

    @abstractmethod
    async def consume_recover_account_token(
        self,
        *,
        token: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[
        ConsumeRecoverAccountTokenResponse, ConsumeRecoverAccountTokenErrorResponse
    ]: ...

    @abstractmethod
    async def register_credential(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        user_context: UserContext,
        recipe_user_id: str,
    ) -> Union[OkResponse, RegisterCredentialErrorResponse]: ...

    @abstractmethod
    async def get_user_from_recover_account_token(
        self,
        *,
        token: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[
        GetUserFromRecoverAccountTokenResponse,
        GetUserFromRecoverAccountTokenErrorResponse,
    ]: ...

    @abstractmethod
    async def remove_credential(
        self,
        *,
        webauthn_credential_id: str,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[OkResponse, RemoveCredentialErrorResponse]: ...

    @abstractmethod
    async def get_credential(
        self,
        *,
        webauthn_credential_id: str,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[GetCredentialResponse, GetCredentialErrorResponse]: ...

    @abstractmethod
    async def list_credentials(
        self,
        *,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> ListCredentialsResponse: ...

    @abstractmethod
    async def remove_generated_options(
        self,
        *,
        webauthn_generated_options_id: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[OkResponse, RemoveGeneratedOptionsErrorResponse]: ...

    @abstractmethod
    async def get_generated_options(
        self,
        *,
        webauthn_generated_options_id: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[GetGeneratedOptionsResponse, GetGeneratedOptionsErrorResponse]: ...

    @abstractmethod
    async def update_user_email(
        self,
        *,
        recipe_user_id: str,
        email: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[OkResponse, UpdateUserEmailErrorResponse]: ...
