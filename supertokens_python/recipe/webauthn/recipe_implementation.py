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

from typing import Any, Dict, List, Optional, Union, cast

from typing_extensions import Unpack

from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import (
    link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info,
)
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    Attestation,
    AuthenticationPayload,
    ConsumeRecoverAccountTokenErrorResponse,
    ConsumeRecoverAccountTokenResponse,
    CreateNewRecipeUserErrorResponse,
    CreateNewRecipeUserResponse,
    CredentialNotFoundErrorResponse,
    DisplayNameEmailInput,
    EmailAlreadyExistsErrorResponse,
    GenerateRecoverAccountTokenErrorResponse,
    GenerateRecoverAccountTokenResponse,
    GetCredentialErrorResponse,
    GetCredentialResponse,
    GetGeneratedOptionsErrorResponse,
    GetGeneratedOptionsResponse,
    GetUserFromRecoverAccountTokenErrorResponse,
    GetUserFromRecoverAccountTokenResponse,
    InvalidAuthenticatorErrorResponse,
    InvalidCredentialsErrorResponse,
    InvalidEmailErrorResponse,
    InvalidOptionsErrorResponse,
    ListCredentialsResponse,
    OptionsNotFoundErrorResponse,
    RecipeInterface,
    RecoverAccountTokenInput,
    RecoverAccountTokenInvalidErrorResponse,
    RegisterCredentialErrorResponse,
    RegisterOptionsErrorResponse,
    RegisterOptionsKwargsInput,
    RegisterOptionsResponse,
    RegistrationPayload,
    RemoveCredentialErrorResponse,
    RemoveGeneratedOptionsErrorResponse,
    ResidentKey,
    SignInErrorResponse,
    SignInOptionsErrorResponse,
    SignInOptionsResponse,
    SignInResponse,
    SignUpErrorResponse,
    SignUpReponse,
    UnknownUserIdErrorResponse,
    UpdateUserEmailErrorResponse,
    UserVerification,
    VerifyCredentialsErrorResponse,
    VerifyCredentialsResponse,
)
from supertokens_python.recipe.webauthn.types.config import NormalisedWebauthnConfig
from supertokens_python.types.base import RecipeUserId, User, UserContext
from supertokens_python.types.response import OkResponseBaseModel


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        *,
        querier: Querier,
        config: NormalisedWebauthnConfig,
    ):
        self.querier = querier
        self.config = config

    async def register_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        timeout: Optional[int] = None,
        attestation: Optional[Attestation] = None,
        tenant_id: str,
        user_context: UserContext,
        supported_algorithm_ids: Optional[List[int]] = None,
        user_verification: Optional[UserVerification] = None,
        user_presence: Optional[bool] = None,
        resident_key: Optional[ResidentKey] = None,
        **kwargs: Unpack[RegisterOptionsKwargsInput],
    ) -> Union[RegisterOptionsResponse, RegisterOptionsErrorResponse]:
        kwargs_obj: Union[DisplayNameEmailInput, RecoverAccountTokenInput]
        has_email_input: bool = False
        has_recover_account_token_input: bool = False

        if "email" in kwargs and kwargs.get("email") is not None:
            has_email_input = True
            kwargs_obj = DisplayNameEmailInput(
                email=kwargs["email"],
                display_name=kwargs.get("display_name"),
            )
        elif (
            "recover_account_token" in kwargs
            and kwargs.get("recover_account_token") is not None
        ):
            has_recover_account_token_input = True
            kwargs_obj = RecoverAccountTokenInput(
                recover_account_token=kwargs["recover_account_token"],
            )
        else:
            raise ValueError(
                "Either 'email' or 'recover_account_token' must be provided in kwargs."
            )

        email: Optional[str] = None
        if has_email_input:
            email = cast(DisplayNameEmailInput, kwargs_obj)["email"]
        elif has_recover_account_token_input:
            token = cast(RecoverAccountTokenInput, kwargs_obj)["recover_account_token"]
            result = await self.get_user_from_recover_account_token(
                token=token,
                tenant_id=tenant_id,
                user_context=user_context,
            )
            if result.status != "OK":
                return result

            user = result.user
            # if the recipeUserId is not present, it means that the user does not have a webauthn login method and we should just use the user id
            # this will make account recovery act as a sign up
            user_id = user.id
            if result.recipe_user_id is not None:
                user_id = result.recipe_user_id.get_as_string()

            # Not using a filter/next here since this could potentially be None
            for login_method in user.login_methods:
                if login_method.recipe_user_id.get_as_string() == user_id:
                    email = login_method.email
                    break
        else:
            raise Exception(
                "should never come here: Either `email` or `recover_aacount_token` should be specified"
            )

        if email is None:
            return InvalidEmailErrorResponse(err="The email is missing")

        validate_result = await self.config.validate_email_address(
            email=email,
            tenant_id=tenant_id,
            user_context=user_context,
        )
        if validate_result:
            return InvalidEmailErrorResponse(err=validate_result)

        display_name: str
        # Doing a double check with `.get` since someone could explicitly pass `None`
        if has_email_input and kwargs.get("display_name") is not None:
            # If email is provided, and `display_name` is provided in kwargs, access directly
            kwargs_display_name = cast(
                DisplayNameEmailInput,
                kwargs_obj,
            )["display_name"]
            # Additional type-cast since Pylance doesn't understand the type narrowing done above
            display_name = cast(str, kwargs_display_name)
        else:
            display_name = email

        query_data: Dict[str, Any] = {
            "email": email,
            "displayName": display_name,
            "relyingPartyName": relying_party_name,
            "relyingPartyId": relying_party_id,
            "origin": origin,
        }

        if timeout is not None:
            query_data["timeout"] = timeout
        if attestation is not None:
            query_data["attestation"] = attestation
        if supported_algorithm_ids is not None:
            query_data["supportedAlgorithmIds"] = supported_algorithm_ids
        if user_verification is not None:
            query_data["userVerification"] = user_verification
        if user_presence is not None:
            query_data["userPresence"] = user_presence
        if resident_key is not None:
            query_data["residentKey"] = resident_key

        response = await self.querier.send_post_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/options/register"),
            data=query_data,
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR":
                return RecoverAccountTokenInvalidErrorResponse()
            if response["status"] == "INVALID_OPTIONS_ERROR":
                return InvalidOptionsErrorResponse()
            if response["status"] == "INVALID_EMAIL_ERROR":
                return InvalidEmailErrorResponse(err=response["err"])

            raise Exception(f"Unknown Error: {response}")

        return RegisterOptionsResponse.from_json(response)

    async def sign_in_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        timeout: Optional[int] = None,
        user_verification: Optional[UserVerification] = None,
        user_presence: Optional[bool] = None,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[SignInOptionsResponse, SignInOptionsErrorResponse]:
        query_data: Dict[str, Any] = {
            "relyingPartyId": relying_party_id,
            "relyingPartyName": relying_party_name,
            "origin": origin,
        }

        if timeout is not None:
            query_data["timeout"] = timeout
        if user_verification is not None:
            query_data["userVerification"] = user_verification
        if user_presence is not None:
            query_data["userPresence"] = user_presence

        response = await self.querier.send_post_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/options/signin"),
            data=query_data,
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "INVALID_OPTIONS_ERROR":
                return InvalidOptionsErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return SignInOptionsResponse.from_json(response)

    async def sign_up(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        tenant_id: str,
        session: Optional[SessionContainer] = None,
        should_try_linking_with_session_user: Optional[bool] = None,
        user_context: UserContext,
    ) -> Union[SignUpReponse, SignUpErrorResponse]:
        response = await self.create_new_recipe_user(
            credential=credential,
            webauthn_generated_options_id=webauthn_generated_options_id,
            tenant_id=tenant_id,
            user_context=user_context,
        )
        if response.status != "OK":
            return response

        link_result = await link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
            tenant_id=tenant_id,
            input_user=response.user,
            recipe_user_id=response.recipe_user_id,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            user_context=user_context,
        )
        if link_result.status != "OK":
            return link_result

        return SignUpReponse(
            status="OK",
            user=link_result.user,
            recipe_user_id=response.recipe_user_id,
        )

    async def sign_in(
        self,
        *,
        credential: AuthenticationPayload,
        webauthn_generated_options_id: str,
        tenant_id: str,
        session: Optional[SessionContainer] = None,
        should_try_linking_with_session_user: Optional[bool] = None,
        user_context: UserContext,
    ) -> Union[SignInResponse, SignInErrorResponse]:
        verify_creds_response = await self.verify_credentials(
            credential=credential,
            webauthn_generated_options_id=webauthn_generated_options_id,
            tenant_id=tenant_id,
            user_context=user_context,
        )
        if verify_creds_response.status != "OK":
            return verify_creds_response

        signed_in_user = verify_creds_response.user

        login_method = next(
            filter(
                lambda lm: lm.recipe_user_id.get_as_string()
                == verify_creds_response.recipe_user_id.get_as_string(),
                verify_creds_response.user.login_methods,
            )
        )

        if not login_method.verified:
            await AccountLinkingRecipe.get_instance().verify_email_for_recipe_user_if_linked_accounts_are_verified(
                user=verify_creds_response.user,
                recipe_user_id=verify_creds_response.recipe_user_id,
                user_context=user_context,
            )

            # We do this so that we get the updated user (in case the above
            # function updated the verification status) and can return that
            updated_user = await get_user(
                verify_creds_response.recipe_user_id.get_as_string(), user_context
            )

            if updated_user is not None:
                signed_in_user = updated_user

        link_result = await link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
            tenant_id=tenant_id,
            input_user=verify_creds_response.user,
            recipe_user_id=verify_creds_response.recipe_user_id,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            user_context=user_context,
        )

        if link_result.status != "OK":
            return link_result

        signed_in_user = link_result.user

        return SignInResponse(
            status="OK",
            user=signed_in_user,
            recipe_user_id=verify_creds_response.recipe_user_id,
        )

    async def verify_credentials(
        self,
        *,
        credential: AuthenticationPayload,
        webauthn_generated_options_id: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[VerifyCredentialsResponse, VerifyCredentialsErrorResponse]:
        response = await self.querier.send_post_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/signin"),
            data={
                # To allow for JSON encoding
                "credential": credential.to_json(),
                "webauthnGeneratedOptionsId": webauthn_generated_options_id,
            },
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "INVALID_CREDENTIALS_ERROR":
                return InvalidCredentialsErrorResponse()
            if response["status"] == "INVALID_OPTIONS_ERROR":
                return InvalidOptionsErrorResponse()
            if response["status"] == "INVALID_AUTHENTICATOR_ERROR":
                return InvalidAuthenticatorErrorResponse(reason=response["reason"])
            if response["status"] == "CREDENTIAL_NOT_FOUND_ERROR":
                return CredentialNotFoundErrorResponse()
            if response["status"] == "UNKNOWN_USER_ID_ERROR":
                return UnknownUserIdErrorResponse()
            if response["status"] == "OPTIONS_NOT_FOUND_ERROR":
                return OptionsNotFoundErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return VerifyCredentialsResponse(
            user=User.from_json(response["user"]),
            recipe_user_id=RecipeUserId(response["recipeUserId"]),
        )

    async def create_new_recipe_user(
        self,
        *,
        credential: RegistrationPayload,
        webauthn_generated_options_id: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[CreateNewRecipeUserResponse, CreateNewRecipeUserErrorResponse]:
        response = await self.querier.send_post_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/signup"),
            data={
                "webauthnGeneratedOptionsId": webauthn_generated_options_id,
                # To allow for JSON encoding
                "credential": credential.to_json(),
            },
            user_context=user_context,
        )

        if response.get("status") != "OK":
            if response["status"] == "EMAIL_ALREADY_EXISTS_ERROR":
                return EmailAlreadyExistsErrorResponse()
            if response["status"] == "OPTIONS_NOT_FOUND_ERROR":
                return OptionsNotFoundErrorResponse()
            if response["status"] == "INVALID_OPTIONS_ERROR":
                return InvalidOptionsErrorResponse()
            if response["status"] == "INVALID_CREDENTIALS_ERROR":
                return InvalidCredentialsErrorResponse()
            if response["status"] == "INVALID_AUTHENTICATOR_ERROR":
                return InvalidAuthenticatorErrorResponse(reason=response["reason"])

            raise Exception(f"Unknown Error: {response}")

        return CreateNewRecipeUserResponse(
            user=User.from_json(response["user"]),
            recipe_user_id=RecipeUserId(response["recipeUserId"]),
        )

    async def generate_recover_account_token(
        self,
        *,
        user_id: str,
        email: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[
        GenerateRecoverAccountTokenResponse, GenerateRecoverAccountTokenErrorResponse
    ]:
        response = await self.querier.send_post_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/user/recover/token"),
            data={"userId": user_id, "email": email},
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "UNKNOWN_USER_ID_ERROR":
                return UnknownUserIdErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return GenerateRecoverAccountTokenResponse.from_json(response)

    async def consume_recover_account_token(
        self,
        *,
        token: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[
        ConsumeRecoverAccountTokenResponse, ConsumeRecoverAccountTokenErrorResponse
    ]:
        response = await self.querier.send_post_request(
            path=NormalisedURLPath(
                f"/{tenant_id}/recipe/webauthn/user/recover/token/consume"
            ),
            data={"token": token},
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR":
                return RecoverAccountTokenInvalidErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return ConsumeRecoverAccountTokenResponse.from_json(response)

    async def register_credential(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[OkResponseBaseModel, RegisterCredentialErrorResponse]:
        response = await self.querier.send_post_request(
            path=NormalisedURLPath("/recipe/webauthn/user/credential/register"),
            data={
                "recipeUserId": recipe_user_id,
                "webauthnGeneratedOptionsId": webauthn_generated_options_id,
                # To allow for JSON encoding
                "credential": credential.to_json(),
            },
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "INVALID_CREDENTIALS_ERROR":
                return InvalidCredentialsErrorResponse()
            if response["status"] == "OPTIONS_NOT_FOUND_ERROR":
                return OptionsNotFoundErrorResponse()
            if response["status"] == "INVALID_OPTIONS_ERROR":
                return InvalidOptionsErrorResponse()
            if response["status"] == "INVALID_AUTHENTICATOR_ERROR":
                return InvalidAuthenticatorErrorResponse(reason=response["reason"])

            raise Exception(f"Unknown Error: {response}")

        return OkResponseBaseModel()

    async def get_user_from_recover_account_token(
        self,
        *,
        token: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[
        GetUserFromRecoverAccountTokenResponse,
        GetUserFromRecoverAccountTokenErrorResponse,
    ]:
        response = await self.querier.send_get_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/user/recover"),
            params={"token": token},
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR":
                return RecoverAccountTokenInvalidErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        recipe_user_id: Optional[RecipeUserId] = None
        if response.get("recipeUserId") is not None:
            recipe_user_id = RecipeUserId(response["recipeUserId"])

        return GetUserFromRecoverAccountTokenResponse(
            user=User.from_json(response["user"]),
            recipe_user_id=recipe_user_id,
        )

    async def remove_credential(
        self,
        *,
        webauthn_credential_id: str,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[OkResponseBaseModel, RemoveCredentialErrorResponse]:
        response = await self.querier.send_delete_request(
            path=NormalisedURLPath("/recipe/webauthn/user/credential/remove"),
            params={
                "recipeUserId": recipe_user_id,
                "webauthnCredentialId": webauthn_credential_id,
            },
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "CREDENTIAL_NOT_FOUND_ERROR":
                return CredentialNotFoundErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return OkResponseBaseModel()

    async def get_credential(
        self,
        *,
        webauthn_credential_id: str,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[GetCredentialResponse, GetCredentialErrorResponse]:
        response = await self.querier.send_get_request(
            path=NormalisedURLPath("/recipe/webauthn/user/credential"),
            params={
                "webauthnCredentialId": webauthn_credential_id,
                "recipeUserId": recipe_user_id,
            },
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "CREDENTIAL_NOT_FOUND_ERROR":
                return CredentialNotFoundErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return GetCredentialResponse.from_json(
            {
                **response,
                "recipeUserId": RecipeUserId(response["recipeUserId"]),
            }
        )

    async def list_credentials(
        self,
        *,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> ListCredentialsResponse:
        response = await self.querier.send_get_request(
            path=NormalisedURLPath("/recipe/webauthn/user/credential/list"),
            params={"recipeUserId": recipe_user_id},
            user_context=user_context,
        )

        return ListCredentialsResponse.from_json(response)

    async def remove_generated_options(
        self,
        *,
        webauthn_generated_options_id: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[OkResponseBaseModel, RemoveGeneratedOptionsErrorResponse]:
        response = await self.querier.send_delete_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/options/remove"),
            params={"webauthnGeneratedOptionsId": webauthn_generated_options_id},
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "OPTIONS_NOT_FOUND_ERROR":
                return RemoveGeneratedOptionsErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return OkResponseBaseModel()

    async def get_generated_options(
        self,
        *,
        webauthn_generated_options_id: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[GetGeneratedOptionsResponse, GetGeneratedOptionsErrorResponse]:
        response = await self.querier.send_get_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/options"),
            params={"webauthnGeneratedOptionsId": webauthn_generated_options_id},
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "OPTIONS_NOT_FOUND_ERROR":
                return OptionsNotFoundErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return GetGeneratedOptionsResponse.from_json(response)

    async def update_user_email(
        self,
        *,
        email: str,
        recipe_user_id: str,
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[OkResponseBaseModel, UpdateUserEmailErrorResponse]:
        response = await self.querier.send_put_request(
            path=NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/user/email"),
            data={"email": email, "recipeUserId": recipe_user_id},
            query_params={},
            user_context=user_context,
        )

        if response["status"] != "OK":
            if response["status"] == "EMAIL_ALREADY_EXISTS_ERROR":
                return EmailAlreadyExistsErrorResponse()
            if response["status"] == "UNKNOWN_USER_ID_ERROR":
                return UnknownUserIdErrorResponse()

            raise Exception(f"Unknown Error: {response}")

        return OkResponseBaseModel()
