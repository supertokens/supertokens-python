from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Literal, Optional, TypedDict, Union

from typing_extensions import NotRequired, Unpack

from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    RecipeInterface,
    RegisterOptionsErrorResponse,
    RegistrationPayload,
    ResidentKey,
    SignInOptionsErrorResponse,
    UserVerification,
)
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.recipe.webauthn.types.config import WebauthnConfig
from supertokens_python.supertokens import AppInfo
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.response import (
    ApiResponseDataclass,
    GeneralErrorResponse,
    OkResponse,
    StatusReasonResponse,
    StatusResponse,
)


@dataclass
class TypeWebauthnRecoverAccountEmailDeliveryInput(ApiResponseDataclass):
    @dataclass
    class User:
        id: str
        recipe_user_id: Optional[RecipeUserId]

    type: Literal["RECOVER_ACCOUNT"]
    user: User
    recover_account_link: str
    tenant_id: str


TypeWebauthnEmailDeliveryInput = TypeWebauthnRecoverAccountEmailDeliveryInput


@dataclass
class APIOptions(ApiResponseDataclass):
    recipe_implementation: RecipeInterface
    appInfo: AppInfo
    config: WebauthnConfig
    recipe_id: str
    is_in_serverless_env: bool
    req: BaseRequest
    res: BaseResponse
    email_delivery: EmailDeliveryIngredient[TypeWebauthnEmailDeliveryInput]


@dataclass
class RegisterOptionsPOSTResponse(OkResponse):
    @dataclass
    class RelyingParty(ApiResponseDataclass):
        id: str
        name: str

    @dataclass
    class User(ApiResponseDataclass):
        id: str
        name: str
        display_name: str

    @dataclass
    class ExcludeCredentials(ApiResponseDataclass):
        id: str
        type: Literal["public-key"]
        transports: List[Literal["ble", "hybrid", "internal", "nfc", "usb"]]

    @dataclass
    class PubKeyCredParams(ApiResponseDataclass):
        alg: int
        type: str

    @dataclass
    class AuthenticatorSelection(ApiResponseDataclass):
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
    attestation: Literal["none", "indirect", "direct", "enterprise"]
    pub_key_cred_params: List[PubKeyCredParams]
    authenticator_selection: AuthenticatorSelection


RegisterOptionsPOSTErrorResponse = RegisterOptionsErrorResponse


@dataclass
class SignInOptionsPOSTResponse(OkResponse):
    webauthn_generated_options_id: str
    created_at: str
    expires_at: str
    rp_id: str
    challenge: str
    timeout: int
    user_verification: UserVerification


SignInOptionsPOSTErrorResponse = SignInOptionsErrorResponse

SignUpPOSTErrorResponse = Union[
    StatusReasonResponse[
        Literal["SIGN_UP_NOT_ALLOWED", "INVALID_AUTHENTICATOR_ERROR"], str
    ],
    StatusResponse[
        Literal[
            "EMAIL_ALREADY_EXISTS_ERROR",
            "INVALID_CREDENTIALS_ERROR",
            "OPTIONS_NOT_FOUND_ERROR",
            "INVALID_OPTIONS_ERROR",
        ]
    ],
]

SignInPOSTErrorResponse = Union[
    StatusResponse[Literal["INVALID_CREDENTIALS_ERROR"]],
    StatusReasonResponse[Literal["SIGN_IN_NOT_ALLOWED"], str],
]

GenerateRecoverAccountTokenPOSTErrorResponse = StatusReasonResponse[
    Literal["RECOVER_ACCOUNT_NOT_ALLOWED"], str
]

RecoverAccountPOSTErrorResponse = Union[
    StatusResponse[
        Literal[
            "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR",
            "INVALID_CREDENTIALS_ERROR",
            "OPTIONS_NOT_FOUND_ERROR",
            "INVALID_OPTIONS_ERROR",
        ]
    ],
    StatusReasonResponse[Literal["INVALID_AUTHENTICATOR_ERROR"], str],
]

RegisterCredentialPOSTErrorResponse = Union[
    StatusResponse[
        Literal[
            "INVALID_CREDENTIALS_ERROR",
            "OPTIONS_NOT_FOUND_ERROR",
            "INVALID_OPTIONS_ERROR",
        ]
    ],
    StatusReasonResponse[
        Literal["REGISTER_CREDENTIAL_NOT_ALLOWED", "INVALID_AUTHENTICATOR_ERROR"], str
    ],
]


@dataclass
class EmailExistsGetResponse(OkResponse):
    exists: bool


@dataclass
class RecoverAccountPOSTResponse(OkResponse):
    user: User
    email: str


@dataclass
class SignUpPOSTResponse(OkResponse):
    user: User
    session: SessionContainer


@dataclass
class SignInPOSTResponse(OkResponse):
    user: User
    session: SessionContainer


class RecoverAccountTokenInput(TypedDict):
    recover_account_token: str


class DisplayNameEmailInput(TypedDict):
    display_name: Optional[str]
    email: str


class RegisterOptionsPOSTKwargsInput(TypedDict):
    recover_account_token: NotRequired[str]
    display_name: NotRequired[str]
    email: NotRequired[str]

class ApiInterface(ABC):
    disable_register_options_post: bool = False
    disable_sign_in_options_post: bool = False
    disable_sign_up_post: bool = False
    disable_sign_in_post: bool = False
    disable_generate_recover_account_token_post: bool = False
    disable_recover_account_post: bool = False
    disable_register_credential_post: bool = False
    disable_email_exists_get: bool = False

    @abstractmethod
    async def register_options_post(
        self,
        *,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
        **kwargs: Unpack[RegisterOptionsPOSTKwargsInput],
    ) -> Union[
        RegisterOptionsPOSTResponse,
        GeneralErrorResponse,
        RegisterOptionsPOSTErrorResponse,
    ]: ...

    @abstractmethod
    async def sign_in_options_post(
        self,
        *,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[
        SignInOptionsPOSTResponse, GeneralErrorResponse, SignInOptionsPOSTErrorResponse
    ]: ...

    @abstractmethod
    async def sign_up_post(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        tenant_id: str,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Optional[bool],
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[SignUpPOSTResponse, GeneralErrorResponse, SignUpPOSTErrorResponse]: ...

    @abstractmethod
    async def sign_in_post(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        tenant_id: str,
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Optional[bool],
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[SignInPOSTResponse, GeneralErrorResponse, SignInPOSTErrorResponse]: ...

    @abstractmethod
    async def generate_recover_account_token_post(
        self,
        *,
        email: str,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[
        OkResponse, GeneralErrorResponse, GenerateRecoverAccountTokenPOSTErrorResponse
    ]: ...

    @abstractmethod
    async def recover_account_post(
        self,
        *,
        token: str,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[
        RecoverAccountPOSTResponse,
        GeneralErrorResponse,
        RecoverAccountPOSTErrorResponse,
    ]: ...

    @abstractmethod
    async def register_credential_post(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        tenant_id: str,
        session: SessionContainer,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[
        OkResponse, GeneralErrorResponse, RegisterCredentialPOSTErrorResponse
    ]: ...

    @abstractmethod
    async def email_exists_get(
        self,
        *,
        email: str,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[EmailExistsGetResponse, GeneralErrorResponse]: ...
