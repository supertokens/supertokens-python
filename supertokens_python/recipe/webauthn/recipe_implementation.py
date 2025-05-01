from typing import Callable, List, Optional, Union, cast

from typing_extensions import Unpack

from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import (
    link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info,
)
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    Attestation,
    AuthenticationPayload,
    ConsumeRecoverAccountTokenErrorResponse,
    ConsumeRecoverAccountTokenResponse,
    CreateNewRecipeUserErrorResponse,
    CreateNewRecipeUserResponse,
    DisplayNameEmailInput,
    GenerateRecoverAccountTokenErrorResponse,
    GenerateRecoverAccountTokenResponse,
    GetCredentialErrorResponse,
    GetCredentialResponse,
    GetGeneratedOptionsErrorResponse,
    GetGeneratedOptionsResponse,
    GetUserFromRecoverAccountTokenErrorResponse,
    GetUserFromRecoverAccountTokenResponse,
    ListCredentialsResponse,
    RecipeInterface,
    RecoverAccountTokenInput,
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
    UpdateUserEmailErrorResponse,
    UserVerification,
    VerifyCredentialsErrorResponse,
    VerifyCredentialsResponse,
)
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.recipe.webauthn.types.config import WebauthnConfig
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.response import OkResponse, StatusErrResponse


class RecipeImplementation(RecipeInterface):
    def __init__(
        self, *, querier: Querier, get_webauthn_config: Callable[[], WebauthnConfig]
    ):
        self.querier = querier
        self.get_webauthn_config = get_webauthn_config

    async def register_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        timeout: Optional[int] = None,
        attestation: Optional[Attestation] = "none",
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

        if "email" in kwargs:
            has_email_input = True
            kwargs_obj = DisplayNameEmailInput(
                email=kwargs["email"],
                display_name=kwargs.get("display_name"),
            )
        elif "recover_account_token" in kwargs:
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
            # TODO: Check with Victor if these types are wrong - recipe_user_id is not defined as optional in Node
            user_id = user.id
            if result.recipe_user_id is not None:
                user_id = result.recipe_user_id.get_as_string()

            # Not using a filter/next here since this could potentially be None
            for login_method in user.login_methods:
                if login_method.recipe_user_id.get_as_string() == user_id:
                    email = login_method.email
                    break

        if email is None:
            return StatusErrResponse(
                status="INVALID_EMAIL_ERROR",
                err="The email is missing",
            )

        validate_result = await self.get_webauthn_config().validate_email_address(
            email=email,
            tenant_id=tenant_id,
            user_context=user_context,
        )
        if validate_result:
            return StatusErrResponse(status="INVALID_EMAIL_ERROR", err=validate_result)

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

        resp = await self.querier.send_post_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/options/register"
            ),
            {
                "email": email,
                "displayName": display_name,
                "relyingPartyName": relying_party_name,
                "relyingPartyId": relying_party_id,
                "origin": origin,
                "timeout": timeout,
                "attestation": attestation,
                "supportedAlgorithmIds": supported_algorithm_ids,
                "userVerification": user_verification,
                "userPresence": user_presence,
                "residentKey": resident_key,
            },
            user_context,
        )

        return cast(Union[RegisterOptionsResponse, RegisterOptionsErrorResponse], resp)

    async def sign_in_options(
        self,
        *,
        relying_party_id: str,
        relying_party_name: str,
        origin: str,
        timeout: Optional[int],
        user_verification: Optional[UserVerification],
        user_presence: Optional[bool],
        tenant_id: str,
        user_context: UserContext,
    ) -> Union[SignInOptionsResponse, SignInOptionsErrorResponse]:
        resp = await self.querier.send_post_request(
            NormalisedURLPath(f"/{tenant_id}/recipe/webauthn/options/signin"),
            {
                "userVerification": user_verification,
                "userPresence": user_presence,
                "relyingPartyId": relying_party_id,
                "relyingPartyName": relying_party_name,
                "origin": origin,
                "timeout": timeout,
            },
            user_context,
        )
        return cast(Union[SignInOptionsResponse, SignInOptionsErrorResponse], resp)

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

        # TODO: Node uses `!= "LINKING_TO_SESSION_USER_FAILED"` - Why? Shouldn't we return ALL error responses as-is?
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
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[VerifyCredentialsResponse, VerifyCredentialsErrorResponse]:
        response = await self.querier.send_post_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/signin"
            ),
            {
                "credential": credential,
                "webauthnGeneratedOptionsId": webauthn_generated_options_id,
            },
            user_context,
        )

        if response.get("status") == "OK":
            return VerifyCredentialsResponse(
                status="OK",
                user=User.from_json(response["user"]),
                recipe_user_id=RecipeUserId(response["recipeUserId"]),
            )

        return cast(VerifyCredentialsErrorResponse, response)

    async def create_new_recipe_user(
        self,
        *,
        credential: RegistrationPayload,
        webauthn_generated_options_id: str,
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[CreateNewRecipeUserResponse, CreateNewRecipeUserErrorResponse]:
        resp = await self.querier.send_post_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/signup"
            ),
            {
                "webauthnGeneratedOptionsId": webauthn_generated_options_id,
                "credential": credential,
            },
            user_context,
        )

        if resp.get("status") == "OK":
            return CreateNewRecipeUserResponse(
                status="OK",
                user=User.from_json(resp["user"]),
                recipe_user_id=RecipeUserId(resp["recipeUserId"]),
            )

        return cast(CreateNewRecipeUserErrorResponse, resp)

    async def generate_recover_account_token(
        self,
        *,
        user_id: str,
        email: str,
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[
        GenerateRecoverAccountTokenResponse, GenerateRecoverAccountTokenErrorResponse
    ]:
        resp = await self.querier.send_post_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/user/recover/token"
            ),
            {"userId": user_id, "email": email},
            user_context,
        )
        return cast(
            Union[
                GenerateRecoverAccountTokenResponse,
                GenerateRecoverAccountTokenErrorResponse,
            ],
            resp,
        )

    async def consume_recover_account_token(
        self,
        *,
        token: str,
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[
        ConsumeRecoverAccountTokenResponse, ConsumeRecoverAccountTokenErrorResponse
    ]:
        resp = await self.querier.send_post_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/user/recover/token/consume"
            ),
            {"token": token},
            user_context,
        )
        return cast(
            Union[
                ConsumeRecoverAccountTokenResponse,
                ConsumeRecoverAccountTokenErrorResponse,
            ],
            resp,
        )

    async def register_credential(
        self,
        *,
        webauthn_generated_options_id: str,
        credential: RegistrationPayload,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[OkResponse, RegisterCredentialErrorResponse]:
        resp = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/webauthn/user/credential/register"),
            {
                "recipeUserId": recipe_user_id,
                "webauthnGeneratedOptionsId": webauthn_generated_options_id,
                "credential": credential,
            },
            user_context,
        )
        return cast(Union[OkResponse, RegisterCredentialErrorResponse], resp)

    async def get_user_from_recover_account_token(
        self,
        *,
        token: str,
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[
        GetUserFromRecoverAccountTokenResponse,
        GetUserFromRecoverAccountTokenErrorResponse,
    ]:
        resp = await self.querier.send_get_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/user/recover"
            ),
            {"token": token},
            user_context,
        )

        if resp.get("status") == "OK":
            return GetUserFromRecoverAccountTokenResponse(
                status="OK",
                user=User.from_json(resp["user"]),
                recipe_user_id=RecipeUserId(resp["recipeUserId"]),
            )

        return cast(GetUserFromRecoverAccountTokenErrorResponse, resp)

    async def remove_credential(
        self,
        *,
        webauthn_credential_id: str,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[OkResponse, RemoveCredentialErrorResponse]:
        resp = await self.querier.send_delete_request(
            NormalisedURLPath("/recipe/webauthn/user/credential/remove"),
            {
                "recipeUserId": recipe_user_id,
                "webauthnCredentialId": webauthn_credential_id,
            },
            user_context,
        )
        return cast(Union[OkResponse, RemoveCredentialErrorResponse], resp)

    async def get_credential(
        self,
        *,
        webauthn_credential_id: str,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> Union[GetCredentialResponse, GetCredentialErrorResponse]:
        resp = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/webauthn/user/credential"),
            {
                "webauthnCredentialId": webauthn_credential_id,
                "recipeUserId": recipe_user_id,
            },
            user_context,
        )

        if resp.get("status") == "OK":
            return GetCredentialResponse(
                status="OK",
                webauthn_credential_id=resp["webauthnCredentialId"],
                relying_party_id=resp["relyingPartyId"],
                recipe_user_id=RecipeUserId(resp["recipeUserId"]),
                created_at=resp["createdAt"],
            )

        return cast(GetCredentialErrorResponse, resp)

    async def list_credentials(
        self,
        *,
        recipe_user_id: str,
        user_context: UserContext,
    ) -> ListCredentialsResponse:
        resp = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/webauthn/user/credential/list"),
            {"recipeUserId": recipe_user_id},
            user_context,
        )
        return cast(ListCredentialsResponse, resp)

    async def remove_generated_options(
        self,
        *,
        webauthn_generated_options_id: str,
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[OkResponse, RemoveGeneratedOptionsErrorResponse]:
        resp = await self.querier.send_delete_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/options/remove"
            ),
            {"webauthnGeneratedOptionsId": webauthn_generated_options_id},
            user_context,
        )
        return cast(Union[OkResponse, RemoveGeneratedOptionsErrorResponse], resp)

    async def get_generated_options(
        self,
        *,
        webauthn_generated_options_id: str,
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[GetGeneratedOptionsResponse, GetGeneratedOptionsErrorResponse]:
        resp = await self.querier.send_get_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/options"
            ),
            {"webauthnGeneratedOptionsId": webauthn_generated_options_id},
            user_context,
        )
        return cast(
            Union[GetGeneratedOptionsResponse, GetGeneratedOptionsErrorResponse], resp
        )

    async def update_user_email(
        self,
        *,
        email: str,
        recipe_user_id: str,
        tenant_id: Optional[str] = None,
        user_context: UserContext,
    ) -> Union[OkResponse, UpdateUserEmailErrorResponse]:
        resp = await self.querier.send_put_request(
            NormalisedURLPath(
                f"/{tenant_id or DEFAULT_TENANT_ID}/recipe/webauthn/user/email"
            ),
            {"email": email, "recipeUserId": recipe_user_id},
            {},
            user_context,
        )
        return cast(Union[OkResponse, UpdateUserEmailErrorResponse], resp)
