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
from typing import List, Literal, Optional, TypedDict, Union

from typing_extensions import NotRequired, Unpack

from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    AuthenticationPayload,
    EmailAlreadyExistsErrorResponse,
    InvalidAuthenticatorErrorResponse,
    InvalidCredentialsErrorResponse,
    InvalidOptionsErrorResponse,
    OptionsNotFoundErrorResponse,
    RecipeInterface,
    RecoverAccountTokenInvalidErrorResponse,
    RegisterOptionsErrorResponse,
    RegistrationPayload,
    ResidentKey,
    SignInOptionsErrorResponse,
    UserVerification,
)
from supertokens_python.recipe.webauthn.types.config import NormalisedWebauthnConfig
from supertokens_python.supertokens import AppInfo
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.base import UserContext
from supertokens_python.types.response import (
    CamelCaseBaseModel,
    GeneralErrorResponse,
    OkResponseBaseModel,
    StatusReasonResponseBaseModel,
)


class SignUpNotAllowedErrorResponse(
    StatusReasonResponseBaseModel[Literal["SIGN_UP_NOT_ALLOWED"], str]
):
    status: Literal["SIGN_UP_NOT_ALLOWED"] = "SIGN_UP_NOT_ALLOWED"


class SignInNotAllowedErrorResponse(
    StatusReasonResponseBaseModel[Literal["SIGN_IN_NOT_ALLOWED"], str]
):
    status: Literal["SIGN_IN_NOT_ALLOWED"] = "SIGN_IN_NOT_ALLOWED"


class RecoverAccountNotAllowedErrorResponse(
    StatusReasonResponseBaseModel[Literal["RECOVER_ACCOUNT_NOT_ALLOWED"], str]
):
    status: Literal["RECOVER_ACCOUNT_NOT_ALLOWED"] = "RECOVER_ACCOUNT_NOT_ALLOWED"


class RegisterCredentialNotAllowedErrorResponse(
    StatusReasonResponseBaseModel[Literal["REGISTER_CREDENTIAL_NOT_ALLOWED"], str]
):
    status: Literal["REGISTER_CREDENTIAL_NOT_ALLOWED"] = (
        "REGISTER_CREDENTIAL_NOT_ALLOWED"
    )


class WebauthnRecoverAccountEmailDeliveryUser(CamelCaseBaseModel):
    id: str
    recipe_user_id: Optional[RecipeUserId]
    email: str


class TypeWebauthnRecoverAccountEmailDeliveryInput(CamelCaseBaseModel):
    type: Literal["RECOVER_ACCOUNT"] = "RECOVER_ACCOUNT"
    user: WebauthnRecoverAccountEmailDeliveryUser
    recover_account_link: str
    tenant_id: str


TypeWebauthnEmailDeliveryInput = TypeWebauthnRecoverAccountEmailDeliveryInput


class APIOptions(CamelCaseBaseModel):
    recipe_implementation: RecipeInterface
    app_info: AppInfo
    config: NormalisedWebauthnConfig
    recipe_id: str
    req: BaseRequest
    res: BaseResponse
    email_delivery: EmailDeliveryIngredient[TypeWebauthnEmailDeliveryInput]


class RegisterOptionsPOSTResponse(OkResponseBaseModel):
    class RelyingParty(CamelCaseBaseModel):
        id: str
        name: str

    class User(CamelCaseBaseModel):
        id: str
        name: str
        display_name: str

    class ExcludeCredentials(CamelCaseBaseModel):
        id: str
        type: Literal["public-key"]
        transports: List[Literal["ble", "hybrid", "internal", "nfc", "usb"]]

    class PubKeyCredParams(CamelCaseBaseModel):
        alg: int
        type: str

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
    attestation: Literal["none", "indirect", "direct", "enterprise"]
    pub_key_cred_params: List[PubKeyCredParams]
    authenticator_selection: AuthenticatorSelection


RegisterOptionsPOSTErrorResponse = RegisterOptionsErrorResponse


class SignInOptionsPOSTResponse(OkResponseBaseModel):
    webauthn_generated_options_id: str
    created_at: int
    expires_at: int
    rp_id: str
    challenge: str
    timeout: int
    user_verification: UserVerification


SignInOptionsPOSTErrorResponse = SignInOptionsErrorResponse

SignUpPOSTErrorResponse = Union[
    SignUpNotAllowedErrorResponse,
    InvalidAuthenticatorErrorResponse,
    EmailAlreadyExistsErrorResponse,
    InvalidCredentialsErrorResponse,
    OptionsNotFoundErrorResponse,
    InvalidOptionsErrorResponse,
]

SignInPOSTErrorResponse = Union[
    InvalidCredentialsErrorResponse,
    SignInNotAllowedErrorResponse,
]

GenerateRecoverAccountTokenPOSTErrorResponse = RecoverAccountNotAllowedErrorResponse

RecoverAccountPOSTErrorResponse = Union[
    RecoverAccountTokenInvalidErrorResponse,
    InvalidCredentialsErrorResponse,
    OptionsNotFoundErrorResponse,
    InvalidOptionsErrorResponse,
    InvalidAuthenticatorErrorResponse,
]

RegisterCredentialPOSTErrorResponse = Union[
    InvalidCredentialsErrorResponse,
    OptionsNotFoundErrorResponse,
    InvalidOptionsErrorResponse,
    RegisterCredentialNotAllowedErrorResponse,
    InvalidAuthenticatorErrorResponse,
]


class EmailExistsGetResponse(OkResponseBaseModel):
    exists: bool


class RecoverAccountPOSTResponse(OkResponseBaseModel):
    user: User
    email: str


class SignUpPOSTResponse(OkResponseBaseModel):
    user: User
    session: SessionContainer


class SignInPOSTResponse(OkResponseBaseModel):
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


class APIInterface(ABC):
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
        credential: AuthenticationPayload,
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
        OkResponseBaseModel,
        GeneralErrorResponse,
        GenerateRecoverAccountTokenPOSTErrorResponse,
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
        OkResponseBaseModel, GeneralErrorResponse, RegisterCredentialPOSTErrorResponse
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
