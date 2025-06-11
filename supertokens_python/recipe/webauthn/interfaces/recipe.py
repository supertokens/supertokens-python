# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

from abc import ABC, abstractmethod
from typing import (
    Any,
    Dict,
    List,
    Literal,
    Optional,
    TypedDict,
    Union,
)

from pydantic import Field, field_serializer
from typing_extensions import NotRequired, Unpack

from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError
from supertokens_python.types.base import UserContext
from supertokens_python.types.response import (
    CamelCaseBaseModel,
    OkResponseBaseModel,
    StatusErrResponseBaseModel,
    StatusReasonResponseBaseModel,
    StatusResponseBaseModel,
)

Base64URLString = str
COSEAlgorithmIdentifier = int

ResidentKey = Literal["required", "preferred", "discouraged"]
UserVerification = Literal["required", "preferred", "discouraged"]
Attestation = Literal["none", "indirect", "direct", "enterprise"]


class RecoverAccountTokenInvalidErrorResponse(
    StatusResponseBaseModel[Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"]]
):
    status: Literal["RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"] = (
        "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"
    )


class InvalidOptionsErrorResponse(
    StatusResponseBaseModel[Literal["INVALID_OPTIONS_ERROR"]]
):
    status: Literal["INVALID_OPTIONS_ERROR"] = "INVALID_OPTIONS_ERROR"


class InvalidEmailErrorResponse(
    StatusErrResponseBaseModel[Literal["INVALID_EMAIL_ERROR"]]
):
    status: Literal["INVALID_EMAIL_ERROR"] = "INVALID_EMAIL_ERROR"


class EmailAlreadyExistsErrorResponse(
    StatusResponseBaseModel[Literal["EMAIL_ALREADY_EXISTS_ERROR"]]
):
    status: Literal["EMAIL_ALREADY_EXISTS_ERROR"] = "EMAIL_ALREADY_EXISTS_ERROR"


class OptionsNotFoundErrorResponse(
    StatusResponseBaseModel[Literal["OPTIONS_NOT_FOUND_ERROR"]]
):
    status: Literal["OPTIONS_NOT_FOUND_ERROR"] = "OPTIONS_NOT_FOUND_ERROR"


class InvalidCredentialsErrorResponse(
    StatusResponseBaseModel[Literal["INVALID_CREDENTIALS_ERROR"]]
):
    status: Literal["INVALID_CREDENTIALS_ERROR"] = "INVALID_CREDENTIALS_ERROR"


class InvalidAuthenticatorErrorResponse(
    StatusReasonResponseBaseModel[Literal["INVALID_AUTHENTICATOR_ERROR"], str]
):
    status: Literal["INVALID_AUTHENTICATOR_ERROR"] = "INVALID_AUTHENTICATOR_ERROR"


class CredentialNotFoundErrorResponse(
    StatusResponseBaseModel[Literal["CREDENTIAL_NOT_FOUND_ERROR"]]
):
    status: Literal["CREDENTIAL_NOT_FOUND_ERROR"] = "CREDENTIAL_NOT_FOUND_ERROR"


class UnknownUserIdErrorResponse(
    StatusResponseBaseModel[Literal["UNKNOWN_USER_ID_ERROR"]]
):
    status: Literal["UNKNOWN_USER_ID_ERROR"] = "UNKNOWN_USER_ID_ERROR"


class CredentialPayloadBase(CamelCaseBaseModel):
    id: str
    rawId: str
    authenticatorAttachment: Optional[
        Literal[
            "platform",
            "cross-platform",
        ]
    ] = None
    # Default value required since inputs come from users, might omit this
    # Not provided in the webauthn authenticator used in backend-sdk-testing
    clientExtensionResults: Dict[str, Any] = Field(default_factory=dict)
    type: Literal["public-key"]


class AuthenticatorAssertionResponseJSON(CamelCaseBaseModel):
    clientDataJSON: Base64URLString
    authenticatorData: Base64URLString
    signature: Base64URLString
    userHandle: Optional[Base64URLString] = None


class AuthenticationPayload(CredentialPayloadBase):
    response: AuthenticatorAssertionResponseJSON


class AuthenticatorAttestationResponseJSON(CamelCaseBaseModel):
    clientDataJSON: Base64URLString
    attestationObject: Base64URLString
    authenticatorData: Optional[Base64URLString] = None
    transports: Optional[
        List[
            Literal[
                "ble",
                "cable",
                "hybrid",
                "internal",
                "nfc",
                "smart-card",
                "usb",
            ]
        ]
    ] = None
    publicKeyAlgorithm: Optional[COSEAlgorithmIdentifier] = None
    publicKey: Optional[Base64URLString] = None


class RegistrationPayload(CredentialPayloadBase):
    response: AuthenticatorAttestationResponseJSON


class CredentialPayload(CredentialPayloadBase):
    class Response(CamelCaseBaseModel):
        client_data_json: str
        attestation_object: str
        transports: Optional[
            List[
                Literal[
                    "ble",
                    "cable",
                    "hybrid",
                    "internal",
                    "nfc",
                    "smart-card",
                    "usb",
                ]
            ]
        ] = None
        user_handle: str

    response: Response


class RegisterOptionsResponse(OkResponseBaseModel):
    # for understanding the response, see https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
    # and https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential

    class RelyingParty(CamelCaseBaseModel):
        id: str
        name: str

    class User(CamelCaseBaseModel):
        id: str
        name: str  # user email
        display_name: str  # user email

    class ExcludeCredentials(CamelCaseBaseModel):
        id: str
        transports: List[
            Literal[
                "ble",
                "hybrid",
                "internal",
                "nfc",
                "usb",
            ]
        ]
        type: Literal["public-key"]

    class PubKeyCredParams(CamelCaseBaseModel):
        # we will default to [-8, -7, -257] as supported algorithms.
        # See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        alg: int
        type: Literal["public-key"]

    class AuthenticatorSelection(CamelCaseBaseModel):
        require_resident_key: bool
        resident_key: ResidentKey
        user_verification: UserVerification

    webauthn_generated_options_id: str
    created_at: int
    expires_at: int
    rp: RelyingParty
    user: User
    challenge: str
    timeout: int
    exclude_credentials: List[ExcludeCredentials]
    attestation: Attestation
    pub_key_cred_params: List[PubKeyCredParams]
    authenticator_selection: AuthenticatorSelection


RegisterOptionsErrorResponse = Union[
    RecoverAccountTokenInvalidErrorResponse,
    InvalidOptionsErrorResponse,
    InvalidEmailErrorResponse,
]


class SignInOptionsResponse(OkResponseBaseModel):
    webauthn_generated_options_id: str
    created_at: int
    expires_at: int
    challenge: str
    timeout: int
    user_verification: UserVerification


SignInOptionsErrorResponse = InvalidOptionsErrorResponse


class CreateNewRecipeUserResponse(OkResponseBaseModel):
    user: User
    recipe_user_id: RecipeUserId

    @field_serializer("user")
    def serialize_user(self, user: User):
        return user.to_json()

    @field_serializer("recipe_user_id")
    def serialize_recipe_user_id(self, rui: RecipeUserId):
        return rui.get_as_string()


CreateNewRecipeUserErrorResponse = Union[
    EmailAlreadyExistsErrorResponse,
    OptionsNotFoundErrorResponse,
    InvalidOptionsErrorResponse,
    InvalidCredentialsErrorResponse,
    InvalidAuthenticatorErrorResponse,
]


class SignUpReponse(OkResponseBaseModel):
    user: User
    recipe_user_id: RecipeUserId

    @field_serializer("user")
    def serialize_user(self, user: User):
        return user.to_json()

    @field_serializer("recipe_user_id")
    def serialize_recipe_user_id(self, rui: RecipeUserId):
        return rui.get_as_string()


SignUpErrorResponse = Union[
    CreateNewRecipeUserErrorResponse,
    LinkingToSessionUserFailedError,
]


class VerifyCredentialsResponse(OkResponseBaseModel):
    user: User
    recipe_user_id: RecipeUserId

    @field_serializer("user")
    def serialize_user(self, user: User):
        return user.to_json()

    @field_serializer("recipe_user_id")
    def serialize_recipe_user_id(self, rui: RecipeUserId):
        return rui.get_as_string()


VerifyCredentialsErrorResponse = Union[
    InvalidCredentialsErrorResponse,
    InvalidOptionsErrorResponse,
    InvalidAuthenticatorErrorResponse,
    CredentialNotFoundErrorResponse,
    UnknownUserIdErrorResponse,
    OptionsNotFoundErrorResponse,
]


class SignInResponse(OkResponseBaseModel):
    user: User
    recipe_user_id: RecipeUserId

    @field_serializer("user")
    def serialize_user(self, user: User):
        return user.to_json()

    @field_serializer("recipe_user_id")
    def serialize_recipe_user_id(self, rui: RecipeUserId):
        return rui.get_as_string()


SignInErrorResponse = Union[
    VerifyCredentialsErrorResponse,
    LinkingToSessionUserFailedError,
]


class GenerateRecoverAccountTokenResponse(OkResponseBaseModel):
    token: str


GenerateRecoverAccountTokenErrorResponse = UnknownUserIdErrorResponse


class ConsumeRecoverAccountTokenResponse(OkResponseBaseModel):
    email: str
    user_id: str


ConsumeRecoverAccountTokenErrorResponse = RecoverAccountTokenInvalidErrorResponse


RegisterCredentialErrorResponse = Union[
    InvalidCredentialsErrorResponse,
    OptionsNotFoundErrorResponse,
    InvalidOptionsErrorResponse,
    InvalidAuthenticatorErrorResponse,
]


class GetUserFromRecoverAccountTokenResponse(OkResponseBaseModel):
    user: User
    recipe_user_id: Optional[RecipeUserId]

    @field_serializer("user")
    def serialize_user(self, user: User):
        return user.to_json()

    @field_serializer("recipe_user_id")
    def serialize_recipe_user_id(self, rui: Optional[RecipeUserId]):
        if rui is None:
            return None

        return rui.get_as_string()


GetUserFromRecoverAccountTokenErrorResponse = RecoverAccountTokenInvalidErrorResponse

RemoveCredentialErrorResponse = CredentialNotFoundErrorResponse


class GetCredentialResponse(OkResponseBaseModel):
    webauthn_credential_id: str
    relying_party_id: str
    recipe_user_id: RecipeUserId
    created_at: int

    @field_serializer("recipe_user_id")
    def serialize_recipe_user_id(self, rui: RecipeUserId):
        return rui.get_as_string()


GetCredentialErrorResponse = CredentialNotFoundErrorResponse


class ListCredentialsResponse(OkResponseBaseModel):
    class Credential(CamelCaseBaseModel):
        webauthn_credential_id: str
        relying_party_id: str
        recipe_user_id: str
        created_at: int

    credentials: List[Credential]


RemoveGeneratedOptionsErrorResponse = OptionsNotFoundErrorResponse


class GetGeneratedOptionsResponse(OkResponseBaseModel):
    webauthn_generated_options_id: str
    relying_party_id: str
    relying_party_name: str
    user_verification: UserVerification
    user_presence: bool
    origin: str
    email: Optional[str]
    timeout: int
    challenge: str
    created_at: int
    expires_at: int


GetGeneratedOptionsErrorResponse = OptionsNotFoundErrorResponse


UpdateUserEmailErrorResponse = Union[
    EmailAlreadyExistsErrorResponse,
    UnknownUserIdErrorResponse,
]


class CreateRecoverAccountLinkResponse(OkResponseBaseModel):
    link: str


class RecoverAccountTokenInput(TypedDict):
    recover_account_token: str


class DisplayNameEmailInput(TypedDict):
    display_name: Optional[str]
    email: str


class RegisterOptionsKwargsInput(TypedDict):
    recover_account_token: NotRequired[str]
    display_name: NotRequired[str]
    email: NotRequired[str]


class RecipeInterface(ABC):
    @abstractmethod
    async def register_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        resident_key: Optional[ResidentKey] = None,
        user_verification: Optional[UserVerification] = None,
        user_presence: Optional[bool] = None,
        attestation: Optional[Attestation] = None,
        supported_algorithm_ids: Optional[List[int]] = None,
        timeout: Optional[int] = None,
        tenant_id: str,
        user_context: UserContext,
        **kwargs: Unpack[RegisterOptionsKwargsInput],
    ) -> Union[RegisterOptionsResponse, RegisterOptionsErrorResponse]: ...

    @abstractmethod
    async def sign_in_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        user_verification: Optional[UserVerification] = None,
        user_presence: Optional[bool] = None,
        timeout: Optional[int] = None,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[SignInOptionsResponse, SignInOptionsErrorResponse]: ...

    @abstractmethod
    async def sign_up(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        session: Optional[SessionContainer] = None,
        should_try_linking_with_session_user: Optional[bool] = None,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[SignUpReponse, SignUpErrorResponse]: ...

    @abstractmethod
    async def sign_in(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: AuthenticationPayload,
        session: Optional[SessionContainer] = None,
        should_try_linking_with_session_user: Optional[bool] = None,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[SignInResponse, SignInErrorResponse]: ...

    @abstractmethod
    async def verify_credentials(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: AuthenticationPayload,
        tenant_id: str,
        user_context: UserContext,
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
    ) -> Union[OkResponseBaseModel, RegisterCredentialErrorResponse]: ...

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
    ) -> Union[OkResponseBaseModel, RemoveCredentialErrorResponse]: ...

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
    ) -> Union[OkResponseBaseModel, RemoveGeneratedOptionsErrorResponse]: ...

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
    ) -> Union[OkResponseBaseModel, UpdateUserEmailErrorResponse]: ...
