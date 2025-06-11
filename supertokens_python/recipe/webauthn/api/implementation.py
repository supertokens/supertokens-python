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

from typing import Optional, Union, cast

from typing_extensions import Unpack

from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import (
    get_authenticating_user_and_add_to_current_tenant_if_required,
    is_fake_email,
    post_auth_checks,
    pre_auth_checks,
)
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.accountlinking.types import (
    AccountInfoWithRecipeId,
    AccountInfoWithRecipeIdAndUserId,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.constants import (
    DEFAULT_REGISTER_OPTIONS_ATTESTATION,
    DEFAULT_REGISTER_OPTIONS_RESIDENT_KEY,
    DEFAULT_REGISTER_OPTIONS_SUPPORTED_ALGORITHM_IDS,
    DEFAULT_REGISTER_OPTIONS_TIMEOUT,
    DEFAULT_REGISTER_OPTIONS_USER_PRESENCE,
    DEFAULT_REGISTER_OPTIONS_USER_VERIFICATION,
    DEFAULT_SIGNIN_OPTIONS_TIMEOUT,
    DEFAULT_SIGNIN_OPTIONS_USER_PRESENCE,
    DEFAULT_SIGNIN_OPTIONS_USER_VERIFICATION,
)
from supertokens_python.recipe.webauthn.interfaces.api import (
    APIInterface,
    APIOptions,
    EmailExistsGetResponse,
    GenerateRecoverAccountTokenPOSTErrorResponse,
    RecoverAccountNotAllowedErrorResponse,
    RecoverAccountPOSTErrorResponse,
    RecoverAccountPOSTResponse,
    RegisterCredentialNotAllowedErrorResponse,
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
    TypeWebauthnEmailDeliveryInput,
    WebauthnRecoverAccountEmailDeliveryUser,
)
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    AuthenticationPayload,
    CredentialNotFoundErrorResponse,
    EmailAlreadyExistsErrorResponse,
    InvalidAuthenticatorErrorResponse,
    InvalidCredentialsErrorResponse,
    InvalidOptionsErrorResponse,
    OptionsNotFoundErrorResponse,
    RecoverAccountTokenInvalidErrorResponse,
    RegistrationPayload,
    UnknownUserIdErrorResponse,
)
from supertokens_python.recipe.webauthn.types.base import (
    WebauthnInfoInput,
)
from supertokens_python.recipe.webauthn.utils import get_recover_account_link
from supertokens_python.types.base import (
    AccountInfoInput,
    LoginMethod,
    RecipeUserId,
    User,
    UserContext,
)
from supertokens_python.types.response import (
    GeneralErrorResponse,
    OkResponseBaseModel,
)
from supertokens_python.utils import (
    get_error_response_reason_from_map,
    log_debug_message,
)


class APIImplementation(APIInterface):
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
            user_verification=DEFAULT_SIGNIN_OPTIONS_USER_VERIFICATION,
            user_presence=DEFAULT_SIGNIN_OPTIONS_USER_PRESENCE,
            origin=origin,
            relying_party_id=relying_party_id,
            relying_party_name=relying_party_name,
            timeout=DEFAULT_SIGNIN_OPTIONS_TIMEOUT,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if response.status != "OK":
            return response

        return SignInOptionsPOSTResponse.from_json(
            {
                **response.to_json(),
                "rp_id": relying_party_id,
            }
        )

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
                account_info=AccountInfoInput(email=email),
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
            return SignUpNotAllowedErrorResponse(
                reason=get_error_response_reason_from_map(
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
            # We should only return the status, because the core also adds a reason for most of these errors
            return sign_up_response

        if isinstance(sign_up_response, InvalidAuthenticatorErrorResponse):
            return InvalidAuthenticatorErrorResponse(reason=sign_up_response.reason)

        if sign_up_response.status != "OK":
            return SignUpNotAllowedErrorResponse(
                reason=get_error_response_reason_from_map(
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
                reason=get_error_response_reason_from_map(
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
            await get_authenticating_user_and_add_to_current_tenant_if_required(
                webauthn=WebauthnInfoInput(credential_id=credential.id),
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
        def email_filter(login_method: LoginMethod) -> bool:
            return (
                login_method.recipe_id == "webauthn"
                and login_method.webauthn is not None
                and credential.id in login_method.webauthn.credential_ids
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
                reason=get_error_response_reason_from_map(
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
                reason=get_error_response_reason_from_map(
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
                reason=get_error_response_reason_from_map(
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
    ]:
        # NOTE: Check for email being a non-string value. This check will likely
        # never evaluate to `true` as there is an upper-level check for the type
        # in validation but kept here to be safe.
        if not isinstance(email, str):  # type: ignore
            raise Exception(
                "Should never come here since we already check that the email "
                "value is a string in validateFormFieldsOrThrowError"
            )

        # This function will be reused in different parts of the flow below.
        async def generate_and_send_recover_account_token(
            primary_user_id: str, recipe_user_id: Optional[RecipeUserId]
        ) -> OkResponseBaseModel:
            # The user ID here can be primary or recipe level
            response = (
                await options.recipe_implementation.generate_recover_account_token(
                    tenant_id=tenant_id,
                    user_id=primary_user_id
                    if recipe_user_id is None
                    else recipe_user_id.get_as_string(),
                    email=email,
                    user_context=user_context,
                )
            )

            if isinstance(response, UnknownUserIdErrorResponse):
                log_debug_message(
                    "Recover account email not sent, unknown user id: "
                    f"{primary_user_id if recipe_user_id is None else recipe_user_id.get_as_string()}"
                )
                return OkResponseBaseModel()

            recover_account_link = get_recover_account_link(
                app_info=options.app_info,
                token=response.token,
                tenant_id=tenant_id,
                request=options.req,
                user_context=user_context,
            )

            log_debug_message(f"Sending recover account email to {email}")
            await options.email_delivery.ingredient_interface_impl.send_email(
                template_vars=TypeWebauthnEmailDeliveryInput(
                    type="RECOVER_ACCOUNT",
                    user=WebauthnRecoverAccountEmailDeliveryUser(
                        id=primary_user_id,
                        recipe_user_id=recipe_user_id,
                        email=email,
                    ),
                    recover_account_link=recover_account_link,
                    tenant_id=tenant_id,
                ),
                user_context=user_context,
            )

            return OkResponseBaseModel()

        # Check if primary_user_id is linked with this email
        users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(email=email),
            do_union_of_account_info=False,
            user_context=user_context,
        )

        # We find the recipe user ID of the webauthn account from the user's list for later use
        webauthn_account: Optional[AccountInfoWithRecipeIdAndUserId] = None
        for user in users:
            for login_method in user.login_methods:
                if (
                    login_method.recipe_id == "webauthn"
                    and login_method.has_same_email_as(email)
                ):
                    webauthn_account = AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                        login_method
                    )
                    break

        # We find the primary user ID from the user's list for later use
        primary_user_associated_with_email: Optional[User] = None
        for user in users:
            if user.is_primary_user:
                primary_user_associated_with_email = user
                break

        # First we check if there even exists a primary user that has the input email
        # If not, then we do the regular flow for recover account
        if primary_user_associated_with_email is None:
            if webauthn_account is None:
                log_debug_message(
                    f"Recover account email not sent, unknown user email: {email}"
                )
                return OkResponseBaseModel()

            if webauthn_account.recipe_user_id is None:
                raise Exception(
                    "This should never happen: `recipe_user_id` should not be None"
                )

            return await generate_and_send_recover_account_token(
                primary_user_id=webauthn_account.recipe_user_id.get_as_string(),
                recipe_user_id=webauthn_account.recipe_user_id,
            )

        # Next we check if there is any login method in which the input email is verified.
        # If that is the case, then it's proven that the user owns the email and we can
        # trust linking of the webauthn account.
        email_verified = False
        for login_method in primary_user_associated_with_email.login_methods:
            if login_method.has_same_email_as(email) and login_method.verified:
                email_verified = True
                break

        # Finally, we check if the primary user has any other email / phone number
        # associated with this account - and if it does, then it means that
        # there is a risk of account takeover, so we do not allow the token to be generated
        has_other_email_or_phone = False
        for login_method in primary_user_associated_with_email.login_methods:
            if (
                login_method.email is not None
                and not login_method.has_same_email_as(email)
            ) or (
                login_method.phone_number is not None
                and login_method.phone_number != email
            ):
                has_other_email_or_phone = True
                break

        if not email_verified and has_other_email_or_phone:
            return RecoverAccountNotAllowedErrorResponse(
                reason=(
                    "Recover account link was not created because of account take over risk. "
                    "Please contact support. (ERR_CODE_001)"
                ),
            )

        should_do_account_linking_response = await AccountLinkingRecipe.get_instance().config.should_do_automatic_account_linking(
            webauthn_account
            if webauthn_account is not None
            else AccountInfoWithRecipeIdAndUserId(
                recipe_id="webauthn", email=email, recipe_user_id=None
            ),
            primary_user_associated_with_email,
            None,
            tenant_id,
            user_context,
        )

        # Now we need to check that if there exists any webauthn user at all
        # for the input email. If not, then it implies that when the token is consumed,
        # then we will create a new user - so we should only generate the token if
        # the criteria for the new user is met.
        if webauthn_account is None:
            # this means that there is no webauthn user that exists for the input email.
            # So we check for the sign up condition and only go ahead if that condition is
            # met.

            # But first we must check if account linking is enabled at all - cause if it's
            # not, then the new webauthn user that will be created in recover account
            # code consume cannot be linked to the primary user - therefore, we should
            # not generate a recover account reset token
            if isinstance(
                should_do_account_linking_response, ShouldNotAutomaticallyLink
            ):
                log_debug_message(
                    "Recover account email not sent, since webauthn user didn't exist, "
                    "and account linking not enabled"
                )
                return OkResponseBaseModel()

            is_sign_up_allowed = await AccountLinkingRecipe.get_instance().is_sign_up_allowed(
                new_user=AccountInfoWithRecipeId(
                    recipe_id="webauthn",
                    email=email,
                ),
                is_verified=True,  # Because when the token is consumed, we will mark the email as verified
                session=None,
                tenant_id=tenant_id,
                user_context=user_context,
            )

            if is_sign_up_allowed:
                # Notice that we pass in the primary user ID here. This means that
                # we will be creating a new webauthn account when the token
                # is consumed and linking it to this primary user.
                return await generate_and_send_recover_account_token(
                    primary_user_id=primary_user_associated_with_email.id,
                    recipe_user_id=None,
                )

            log_debug_message(
                f"Recover account email not sent, is_sign_up_allowed returned false for email: {email}"
            )
            return OkResponseBaseModel()

        # At this point, we know that some webauthn user exists with this email
        # and also some primary user ID exist. We now need to find out if they are linked
        # together or not. If they are linked together, then we can just generate the token
        # else we check for more security conditions (since we will be linking them post token generation)
        are_the_two_accounts_linked = False
        for login_method in primary_user_associated_with_email.login_methods:
            # `webauthn_account.recipe_user_id` is guaranteed to be not None
            if (
                login_method.recipe_user_id.get_as_string()
                == webauthn_account.recipe_user_id.get_as_string()  # type: ignore
            ):
                are_the_two_accounts_linked = True
                break

        if are_the_two_accounts_linked:
            return await generate_and_send_recover_account_token(
                primary_user_associated_with_email.id, webauthn_account.recipe_user_id
            )

        # Here we know that the two accounts are NOT linked. We now need to check for an
        # extra security measure here to make sure that the input email in the primary user
        # is verified, and if not, we need to make sure that there is no other email / phone number
        # associated with the primary user account. If there is, then we do not proceed.

        # This security measure helps prevent the following attack:
        # An attacker has email A and they create an account using TP and it doesn't matter if A is verified or not.
        # Now they create another account using the webauthn with email A and verifies it. Both these accounts are linked.
        # Now the attacker changes the email for webauthn recipe to B which makes the webauthn account unverified, but
        # it's still linked.

        # If the real owner of B tries to signup using webauthn, it will say that the account already exists so they may
        # try to recover the account which should be denied because then they will end up getting access to attacker's
        # account and verify the webauthn account.

        # The problem with this situation is if the webauthn account is verified, it will allow further sign-ups with
        # email B which will also be linked to this primary account (that the attacker had created with email A).

        # It is important to realize that the attacker had created another account with A because if they hadn't done that,
        # then they wouldn't have access to this account after the real user recovers the account which is why it is
        # important to check there is another non-webauthn account linked to the primary such that the email is not the same as B.

        # Exception to the above is that, if there is a third recipe account linked to the above two accounts and
        # has B as verified, then we should allow recover account token generation because user has already proven that the
        # owns the email B

        # But first, this only matters it the user cares about checking for email verification status.

        if isinstance(should_do_account_linking_response, ShouldNotAutomaticallyLink):
            if webauthn_account.recipe_user_id is None:
                raise Exception(
                    "This should never happen: `recipe_user_id` should not be None"
                )
            # here we will go ahead with the token generation cause
            # even when the token is consumed, we will not be linking the accounts
            # so no need to check for anything
            return await generate_and_send_recover_account_token(
                primary_user_id=webauthn_account.recipe_user_id.get_as_string(),
                recipe_user_id=webauthn_account.recipe_user_id,
            )

        if should_do_account_linking_response.should_require_verification:
            # the checks below are related to email verification, and if the user
            # does not care about that, then we should just continue with token generation
            return await generate_and_send_recover_account_token(
                primary_user_id=primary_user_associated_with_email.id,
                recipe_user_id=webauthn_account.recipe_user_id,
            )

        return await generate_and_send_recover_account_token(
            primary_user_id=primary_user_associated_with_email.id,
            recipe_user_id=webauthn_account.recipe_user_id,
        )

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
    ]:
        async def mark_email_as_verified(recipe_user_id: RecipeUserId, email: str):
            email_verification_instance = (
                EmailVerificationRecipe.get_instance_optional()
            )
            if email_verification_instance is not None:
                token_response = await email_verification_instance.recipe_implementation.create_email_verification_token(
                    tenant_id=tenant_id,
                    recipe_user_id=recipe_user_id,
                    email=email,
                    user_context=user_context,
                )

                if token_response.status == "OK":
                    await email_verification_instance.recipe_implementation.verify_email_using_token(
                        tenant_id=tenant_id,
                        token=token_response.token,
                        # We pass a false here since we do account-linking in this API
                        # after this function is called
                        attempt_account_linking=False,
                        user_context=user_context,
                    )

        async def do_register_credential_and_verify_email_and_try_link_if_not_primary(
            recipe_user_id: RecipeUserId,
        ) -> Union[
            RecoverAccountPOSTResponse,
            InvalidCredentialsErrorResponse,
            OptionsNotFoundErrorResponse,
            InvalidOptionsErrorResponse,
            InvalidAuthenticatorErrorResponse,
            GeneralErrorResponse,
        ]:
            update_response = await options.recipe_implementation.register_credential(
                webauthn_generated_options_id=webauthn_generated_options_id,
                credential=credential,
                recipe_user_id=recipe_user_id.get_as_string(),
                user_context=user_context,
            )

            if isinstance(
                update_response,
                (
                    InvalidAuthenticatorErrorResponse,
                    InvalidOptionsErrorResponse,
                    OptionsNotFoundErrorResponse,
                    InvalidCredentialsErrorResponse,
                ),
            ):
                return update_response

            # Status == "OK"
            # If the update was successful, we try to mark the email as verified.
            # We do this because we assume that the recover account token was delivered by email
            # (and to the appropriate email address)
            # so consuming it means that the user actually has access to the emails we send.

            # We only do this if the recover account was successful, otherwise the following scenario is possible:
            # 1. User M: signs up using the email of user V with their own credential. They can't validate the email,
            #    because it is not their own.
            # 2. User A: tries signing up but sees the email already exists message
            # 3. User A: recovers the account, but somehow this fails
            # If we verified (and linked) the existing user with the original credential, User M would get access to the
            # current user and any linked users.

            await mark_email_as_verified(
                recipe_user_id=recipe_user_id, email=email_for_whom_token_was_generated
            )
            # We refresh the user information here, because the verification status may be updated, which is used during linking.
            updated_user_after_email_verification = await get_user(
                user_id=recipe_user_id.get_as_string(),
                user_context=user_context,
            )
            if updated_user_after_email_verification is None:
                raise Exception(
                    "This should never happen: user deleted during recover account"
                )

            if updated_user_after_email_verification.is_primary_user:
                # If the user is a primary user, we do not need to do any linking
                return RecoverAccountPOSTResponse(
                    user=updated_user_after_email_verification,
                    email=email_for_whom_token_was_generated,
                )

            # If the user is not primary:
            # Now we try and link the accounts.
            # The function below will try and also create a primary user of the new account, this can happen if:
            # 1. the user was unverified and linking requires verification
            # We do not take try linking by session here, since this is supposed to be called without a session
            # Still, the session object is passed around because it is a required input for shouldDoAutomaticAccountLinking
            link_response = await AccountLinkingRecipe.get_instance().try_linking_by_account_info_or_create_primary_user(
                tenant_id=tenant_id,
                input_user=updated_user_after_email_verification,
                session=None,
                user_context=user_context,
            )
            user_after_we_tried_linking = (
                # Explicit cast since we will have a user when the status is OK
                cast(User, link_response.user)
                if link_response.status == "OK"
                else updated_user_after_email_verification
            )
            return RecoverAccountPOSTResponse(
                email=email_for_whom_token_was_generated,
                user=user_after_we_tried_linking,
            )

        token_consumption_response = (
            await options.recipe_implementation.consume_recover_account_token(
                token=token,
                tenant_id=tenant_id,
                user_context=user_context,
            )
        )

        if isinstance(
            token_consumption_response, RecoverAccountTokenInvalidErrorResponse
        ):
            return token_consumption_response

        user_id_for_whom_token_was_generated = token_consumption_response.user_id
        email_for_whom_token_was_generated = token_consumption_response.email

        existing_user = await get_user(
            user_id=token_consumption_response.user_id,
            user_context=user_context,
        )

        if existing_user is None:
            # This should happen only cause of a race condition where the user
            # might be deleted before token creation and consumption.
            # Also note that this being undefined doesn't mean that the webauthn
            # user does not exist, but it means that there is no recipe or primary user
            # for whom the token was generated.
            return RecoverAccountTokenInvalidErrorResponse()

        if not existing_user.is_primary_user:
            # This means that the existing user is not a primary account, which implies that
            # it must be a non linked webauthn account. In this case, we simply update the credential.
            # Linking to an existing account will be done after the user goes through the email
            # verification flow once they log in (if applicable).
            return await do_register_credential_and_verify_email_and_try_link_if_not_primary(
                recipe_user_id=RecipeUserId(
                    recipe_user_id=user_id_for_whom_token_was_generated
                )
            )

        # User is a primary user
        # If this user contains an webauthn account for whom the token was generated,
        # then we update that user's credential.
        webauthn_user_is_linked_to_existing_user = False
        for login_method in existing_user.login_methods:
            if (
                login_method.recipe_id == "webauthn"
                and login_method.recipe_user_id.get_as_string()
                == user_id_for_whom_token_was_generated
            ):
                webauthn_user_is_linked_to_existing_user = True
                break

        if webauthn_user_is_linked_to_existing_user:
            return await do_register_credential_and_verify_email_and_try_link_if_not_primary(
                recipe_user_id=RecipeUserId(
                    recipe_user_id=user_id_for_whom_token_was_generated
                )
            )

        # This means that the existingUser does not have an webauthn user associated
        # with it. It could now mean that no webauthn user exists, or it could mean that
        # the the webauthn user exists, but it's not linked to the current account.
        # If a webauthn user doesn't exist, we will create one, and link it to the existing account.
        # If webauthn user exists, then it means there is some race condition cause
        # then the token should have been generated for that user instead of the primary user,
        # and it shouldn't have come into this branch. So we can simply send a recover account
        # invalid error and the user can try again.

        # NOTE: We do not ask the dev if we should do account linking or not here
        # cause we already have asked them this when generating an recover account reset token.
        # In the edge case that the dev changes account linking allowance from true to false
        # when it comes here, only a new recipe user id will be created and not linked
        # cause createPrimaryUserIdOrLinkAccounts will disallow linking. This doesn't
        # really cause any security issue.
        create_user_response = (
            await options.recipe_implementation.create_new_recipe_user(
                tenant_id=tenant_id,
                webauthn_generated_options_id=webauthn_generated_options_id,
                credential=credential,
                user_context=user_context,
            )
        )

        if isinstance(
            create_user_response,
            (
                InvalidCredentialsErrorResponse,
                OptionsNotFoundErrorResponse,
                InvalidOptionsErrorResponse,
                InvalidAuthenticatorErrorResponse,
            ),
        ):
            return create_user_response

        if isinstance(create_user_response, EmailAlreadyExistsErrorResponse):
            # this means that the user already existed and we can just return an invalid
            # token (see the above comment)
            return RecoverAccountTokenInvalidErrorResponse()

        # we mark the email as verified because recover account also requires
        # access to the email to work.. This has a good side effect that
        # any other login method with the same email in existingAccount will also get marked
        # as verified.
        await mark_email_as_verified(
            recipe_user_id=create_user_response.user.login_methods[0].recipe_user_id,
            email=token_consumption_response.email,
        )
        updated_user = await get_user(
            user_id=create_user_response.user.id, user_context=user_context
        )
        if updated_user is None:
            raise Exception(
                "This should never happen: user deleted during recover account"
            )
        create_user_response.user = updated_user

        # Now we try and link the accounts. The function below will try and also
        # create a primary user of the new account, and if it does that, it's OK..
        # But in most cases, it will end up linking to existing account since the
        # email is shared.
        # We do not take try linking by session here, since this is supposed to be called without a session
        # Still, the session object is passed around because it is a required input for shouldDoAutomaticAccountLinking
        link_response = await AccountLinkingRecipe.get_instance().try_linking_by_account_info_or_create_primary_user(
            tenant_id=tenant_id,
            input_user=create_user_response.user,
            session=None,
            user_context=user_context,
        )

        # Link response user will always be non-None if status == "OK"
        user_after_linking = (
            cast(User, link_response.user)
            if link_response.status == "OK"
            else create_user_response.user
        )

        if (
            link_response.status == "OK"
            and cast(User, link_response.user).id != existing_user.id
        ):
            # this means that the account we just linked to
            # was not the one we had expected to link it to. This can happen
            # due to some race condition or the other.. Either way, this
            # is not an issue and we can just return OK
            pass

        return RecoverAccountPOSTResponse(
            email=token_consumption_response.email,
            user=user_after_linking,
        )

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
        OkResponseBaseModel,
        GeneralErrorResponse,
        RegisterCredentialPOSTErrorResponse,
    ]:
        error_code_map = {
            "REGISTER_CREDENTIAL_NOT_ALLOWED": "Cannot register credential due to security reasons. Please try logging in, use a different login method or contact support. (ERR_CODE_007)",
            "INVALID_AUTHENTICATOR_ERROR": "The device used for authentication is not supported. Please use a different device. (ERR_CODE_026)",
            "INVALID_CREDENTIALS_ERROR": "The credentials are incorrect. Please make sure you are using the correct credentials. (ERR_CODE_025)",
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
        if not isinstance(email, str):  # type: ignore
            raise Exception(
                "Should never come here since we already check that the email "
                "value is a string in validate_email_address"
            )

        register_credential_response = (
            await options.recipe_implementation.register_credential(
                webauthn_generated_options_id=webauthn_generated_options_id,
                credential=credential,
                user_context=user_context,
                recipe_user_id=session.get_recipe_user_id().get_as_string(),
            )
        )

        if register_credential_response.status != "OK":
            return RegisterCredentialNotAllowedErrorResponse(
                reason=get_error_response_reason_from_map(
                    response_status=register_credential_response.status,
                    error_code_map=error_code_map,
                )
            )

        return OkResponseBaseModel()

    async def email_exists_get(
        self,
        *,
        email: str,
        tenant_id: str,
        options: APIOptions,
        user_context: UserContext,
    ) -> Union[EmailExistsGetResponse, GeneralErrorResponse]:
        users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(email=email),
            do_union_of_account_info=False,
            user_context=user_context,
        )

        webauthn_user_exists = False
        for user in users:
            for login_method in user.login_methods:
                if (
                    login_method.recipe_id == "webauthn"
                    and login_method.has_same_email_as(email)
                ):
                    webauthn_user_exists = True
                    break

        return EmailExistsGetResponse(exists=webauthn_user_exists)
