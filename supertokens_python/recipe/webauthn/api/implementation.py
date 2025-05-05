from typing import Dict, Optional, Union

from typing_extensions import Unpack

from supertokens_python.auth_utils import (
    get_authenticating_user_and_add_to_current_tenant_if_required,
    is_fake_email,
    post_auth_checks,
    pre_auth_checks,
)
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.constants import (
    DEFAULT_REGISTER_OPTIONS_ATTESTATION,
    DEFAULT_REGISTER_OPTIONS_RESIDENT_KEY,
    DEFAULT_REGISTER_OPTIONS_SUPPORTED_ALGORITHM_IDS,
    DEFAULT_REGISTER_OPTIONS_TIMEOUT,
    DEFAULT_REGISTER_OPTIONS_USER_PRESENCE,
    DEFAULT_REGISTER_OPTIONS_USER_VERIFICATION,
)
from supertokens_python.recipe.webauthn.interfaces.api import (
    ApiInterface,
    APIOptions,
    EmailExistsGetResponse,
    GenerateRecoverAccountTokenPOSTErrorResponse,
    RecoverAccountPOSTErrorResponse,
    RecoverAccountPOSTResponse,
    RegisterCredentialPOSTErrorResponse,
    RegisterOptionsPOSTErrorResponse,
    RegisterOptionsPOSTKwargsInput,
    RegisterOptionsPOSTResponse,
    SignInNotAllowedErrorResponse,
    SignInOptionsPOSTErrorResponse,
    SignInOptionsPOSTResponse,
    SignInPOSTErrorResponse,
    SignInPOSTResponse,
    SignUpNotAllowedErrorResponse,
    SignUpPOSTErrorResponse,
    SignUpPOSTResponse,
)
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    AuthenticationPayload,
    CredentialNotFoundErrorResponse,
    EmailAlreadyExistsErrorResponse,
    InvalidAuthenticatorErrorResponse,
    InvalidCredentialsErrorResponse,
    InvalidOptionsErrorResponse,
    OptionsNotFoundErrorResponse,
    RegistrationPayload,
    UnknownUserIdErrorResponse,
)
from supertokens_python.recipe.webauthn.types.base import UserContext, WebauthnInfo
from supertokens_python.types.base import AccountInfo, LoginMethod
from supertokens_python.types.response import (
    GeneralErrorResponse,
    OkResponseBaseModel,
)


# TODO: Move to a common ST module
def get_error_response_reason(
    response_status: str,
    error_code_map: Dict[str, Union[str, Dict[str, str]]],
) -> str:
    reason_map_like = error_code_map[response_status]
    if isinstance(reason_map_like, dict):
        reason = reason_map_like[response_status]
    else:
        reason = reason_map_like

    return reason


class ApiImplementation(ApiInterface):
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
    ]:
        relying_party_id = await options.config.get_relying_party_id(
            tenant_id=tenant_id,
            request=options.req,
            user_context=user_context,
        )
        relying_party_name = await options.config.get_relying_party_name(
            tenant_id=tenant_id,
            request=options.req,
            user_context=user_context,
        )
        origin = await options.config.get_origin(
            tenant_id=tenant_id,
            request=options.req,
            user_context=user_context,
        )

        response = await options.recipe_implementation.register_options(
            **kwargs,
            relying_party_id=relying_party_id,
            relying_party_name=relying_party_name,
            origin=origin,
            resident_key=DEFAULT_REGISTER_OPTIONS_RESIDENT_KEY,
            user_verification=DEFAULT_REGISTER_OPTIONS_USER_VERIFICATION,
            user_presence=DEFAULT_REGISTER_OPTIONS_USER_PRESENCE,
            attestation=DEFAULT_REGISTER_OPTIONS_ATTESTATION,
            supported_algorithm_ids=DEFAULT_REGISTER_OPTIONS_SUPPORTED_ALGORITHM_IDS,
            timeout=DEFAULT_REGISTER_OPTIONS_TIMEOUT,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if response.status != "OK":
            return response

        return RegisterOptionsPOSTResponse.from_json(response.to_json())

    async def sign_in_options_post(
        self,
        *,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[
        SignInOptionsPOSTResponse,
        GeneralErrorResponse,
        SignInOptionsPOSTErrorResponse,
    ]:
        relying_party_id = await options.config.get_relying_party_id(
            tenant_id=tenant_id,
            request=options.req,
            user_context=user_context,
        )
        relying_party_name = await options.config.get_relying_party_name(
            tenant_id=tenant_id,
            request=options.req,
            user_context=user_context,
        )
        # use this to get the full url instead of only the domain url
        origin = await options.config.get_origin(
            tenant_id=tenant_id,
            request=options.req,
            user_context=user_context,
        )

        response = await options.recipe_implementation.sign_in_options(
            user_verification=DEFAULT_REGISTER_OPTIONS_USER_VERIFICATION,
            user_presence=DEFAULT_REGISTER_OPTIONS_USER_PRESENCE,
            origin=origin,
            relying_party_id=relying_party_id,
            relying_party_name=relying_party_name,
            timeout=DEFAULT_REGISTER_OPTIONS_TIMEOUT,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if response.status != "OK":
            return response

        return SignInOptionsPOSTResponse.from_json(response.to_json())

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
    ) -> Union[SignUpPOSTResponse, GeneralErrorResponse, SignUpPOSTErrorResponse]:
        error_code_map = {
            "SIGN_UP_NOT_ALLOWED": "Cannot sign up due to security reasons. Please try logging in, use a different login method or contact support. (ERR_CODE_025)",
            "LINKING_TO_SESSION_USER_FAILED": {
                "EMAIL_VERIFICATION_REQUIRED": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_026)",
                "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_027)",
                "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_028)",
                "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_029)",
            },
        }

        generated_options = await options.recipe_implementation.get_generated_options(
            webauthn_generated_options_id=webauthn_generated_options_id,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if generated_options.status != "OK":
            return generated_options

        email = generated_options.email

        # NOTE: Following checks will likely never throw an error as the
        # check for type is done in a parent function but they are kept
        # here to be on the safe side.
        if not email:
            raise Exception(
                "Should never come here since we already check that the email "
                "value is a string in validate_email_address"
            )

        pre_auth_checks_response = await pre_auth_checks(
            authenticating_account_info=AccountInfoWithRecipeId(
                recipe_id="webauthn",
                email=email,
            ),
            factor_ids=["webauthn"],
            is_sign_up=True,
            is_verified=is_fake_email(email),
            sign_in_verifies_login_method=False,
            skip_session_user_update_in_core=False,
            authenticating_user=None,  # since this is a sign up
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if pre_auth_checks_response.status == "SIGN_UP_NOT_ALLOWED":
            conflicting_users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
                tenant_id=tenant_id,
                account_info=AccountInfo(email=email),
                do_union_of_account_info=False,
                user_context=user_context,
            )

            for user in conflicting_users:
                for login_method in user.login_methods:
                    if (
                        login_method.recipe_id == "webauthn"
                        and login_method.has_same_email_as(email)
                    ):
                        return EmailAlreadyExistsErrorResponse()

        if pre_auth_checks_response.status != "OK":
            # TODO: Do we need to implement a new SignUpPostNotAllowedErrorResponse class?
            return SignUpNotAllowedErrorResponse(
                reason=get_error_response_reason(
                    response_status=pre_auth_checks_response.status,
                    error_code_map=error_code_map,
                )
            )

        if is_fake_email(email) and pre_auth_checks_response.is_first_factor:
            # Fake emails cannot be used as a first factor
            return EmailAlreadyExistsErrorResponse()

        sign_up_response = await options.recipe_implementation.sign_up(
            webauthn_generated_options_id=webauthn_generated_options_id,
            credential=credential,
            tenant_id=tenant_id,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            user_context=user_context,
        )

        if isinstance(
            sign_up_response,
            (
                EmailAlreadyExistsErrorResponse,
                InvalidCredentialsErrorResponse,
                InvalidOptionsErrorResponse,
                OptionsNotFoundErrorResponse,
            ),
        ):
            # TODO: Node says this will return a `reason`, but I don't see reason defined in `signUp`'s responses
            return sign_up_response

        # TODO: If above snippet is fine, just return this error as well from the same block
        if isinstance(sign_up_response, InvalidAuthenticatorErrorResponse):
            return InvalidAuthenticatorErrorResponse(reason=sign_up_response.reason)

        if sign_up_response.status != "OK":
            return SignUpNotAllowedErrorResponse(
                reason=get_error_response_reason(
                    response_status=sign_up_response.status,
                    error_code_map=error_code_map,
                )
            )

        post_auth_checks_response = await post_auth_checks(
            authenticated_user=sign_up_response.user,
            recipe_user_id=sign_up_response.recipe_user_id,
            is_sign_up=True,
            factor_id="webauthn",
            session=session,
            request=options.req,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if post_auth_checks_response.status != "OK":
            # It should never actually come here, but we do it cause of consistency.
            # If it does come here (in case there is a bug), it would make this conditional throw
            # anyway, cause there is no SIGN_IN_NOT_ALLOWED in the errorCodeMap.
            return SignUpNotAllowedErrorResponse(
                reason=get_error_response_reason(
                    response_status=post_auth_checks_response.status,
                    error_code_map=error_code_map,
                )
            )

        return SignUpPOSTResponse(
            session=post_auth_checks_response.session,
            user=post_auth_checks_response.user,
        )

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
    ) -> Union[SignInPOSTResponse, GeneralErrorResponse, SignInPOSTErrorResponse]:
        error_code_map = {
            "SIGN_IN_NOT_ALLOWED": "Cannot sign in due to security reasons. Please try recovering your account, use a different login method or contact support. (ERR_CODE_030)",
            "LINKING_TO_SESSION_USER_FAILED": {
                "EMAIL_VERIFICATION_REQUIRED": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_031)",
                "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_032)",
                "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_033)",
                "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_034)",
            },
        }

        verify_result_response = await options.recipe_implementation.verify_credentials(
            credential=credential,
            webauthn_generated_options_id=webauthn_generated_options_id,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if verify_result_response.status != "OK":
            return InvalidCredentialsErrorResponse()

        generated_options_response = (
            await options.recipe_implementation.get_generated_options(
                webauthn_generated_options_id=webauthn_generated_options_id,
                tenant_id=tenant_id,
                user_context=user_context,
            )
        )

        if generated_options_response.status != "OK":
            return InvalidCredentialsErrorResponse()

        async def check_credentials_on_tenant(tenant_id: str):
            return True

        authenticating_user = (
            # TODO: Update this method to use `webauthn`
            await get_authenticating_user_and_add_to_current_tenant_if_required(
                webauthn=WebauthnInfo(credential_id=credential.id),
                user_context=user_context,
                recipe_id="webauthn",
                session=session,
                tenant_id=tenant_id,
                check_credentials_on_tenant=check_credentials_on_tenant,
                email=None,
                phone_number=None,
                third_party=None,
            )
        )

        is_verified = (
            authenticating_user is not None
            and authenticating_user.login_method is not None
            and authenticating_user.login_method.verified
        )

        # We check this before preAuthChecks, because that function assumes that if isSignUp is false,
        # then authenticatingUser is defined. While it wouldn't technically cause any problems with
        # the implementation of that function, this way we can guarantee that either isSignInAllowed or
        # isSignUpAllowed will be called as expected.
        if authenticating_user is None:
            return InvalidCredentialsErrorResponse()

        # We find the email of the user that has the same credentialId as the one we are verifying
        # TODO: Update `LoginMethod` to have `webauthn` field
        def email_filter(login_method: LoginMethod) -> bool:
            return (
                login_method.recipe_id == "webauthn"
                and login_method.webauthn is not None
                and credential.id in login_method.webauthn.credential_id
            )

        email = next(filter(email_filter, authenticating_user.user.login_methods), None)
        if email is None or email.email is None:
            raise Exception("This should never happen: webauthn user has no email")

        email = email.email

        pre_auth_checks_response = await pre_auth_checks(
            authenticating_account_info=AccountInfoWithRecipeId(
                recipe_id="webauthn",
                email=email,
            ),
            factor_ids=["webauthn"],
            is_sign_up=False,
            authenticating_user=authenticating_user.user,
            is_verified=is_verified,
            sign_in_verifies_login_method=False,
            skip_session_user_update_in_core=False,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )
        if pre_auth_checks_response.status == "SIGN_IN_NOT_ALLOWED":
            raise Exception(
                "This should never happen: pre-auth checks should not fail for sign in"
            )
        if pre_auth_checks_response.status != "OK":
            return SignInNotAllowedErrorResponse(
                reason=get_error_response_reason(
                    response_status=pre_auth_checks_response.status,
                    error_code_map=error_code_map,
                )
            )

        if is_fake_email(email) and pre_auth_checks_response.is_first_factor:
            # Fake emails cannot be used as a first factor
            return InvalidCredentialsErrorResponse()

        sign_in_response = await options.recipe_implementation.sign_in(
            webauthn_generated_options_id=webauthn_generated_options_id,
            credential=credential,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if isinstance(sign_in_response, InvalidCredentialsErrorResponse):
            return sign_in_response

        if isinstance(
            sign_in_response,
            (
                InvalidOptionsErrorResponse,
                InvalidAuthenticatorErrorResponse,
                CredentialNotFoundErrorResponse,
                UnknownUserIdErrorResponse,
                OptionsNotFoundErrorResponse,
            ),
        ):
            return InvalidCredentialsErrorResponse()

        if sign_in_response.status != "OK":
            return SignInNotAllowedErrorResponse(
                reason=get_error_response_reason(
                    response_status=sign_in_response.status,
                    error_code_map=error_code_map,
                )
            )

        post_auth_checks_response = await post_auth_checks(
            authenticated_user=sign_in_response.user,
            recipe_user_id=sign_in_response.recipe_user_id,
            is_sign_up=False,
            factor_id="webauthn",
            session=session,
            request=options.req,
            tenant_id=tenant_id,
            user_context=user_context,
        )
        if post_auth_checks_response.status != "OK":
            return SignInNotAllowedErrorResponse(
                reason=get_error_response_reason(
                    response_status=post_auth_checks_response.status,
                    error_code_map=error_code_map,
                )
            )

        return SignInPOSTResponse(
            session=post_auth_checks_response.session,
            user=post_auth_checks_response.user,
        )

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

    async def email_exists_get(
        self,
        *,
        email: str,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[EmailExistsGetResponse, GeneralErrorResponse]: ...
