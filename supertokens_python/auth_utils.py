from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.exceptions import BadInputError, raise_bad_input_exception
from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.accountlinking import (
    AccountInfoWithRecipeIdAndUserId,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.accountlinking.utils import (
    recipe_init_defined_should_do_automatic_account_linking,
)
from supertokens_python.recipe.emailverification import (
    EmailVerificationClaim,
)
from supertokens_python.recipe.multifactorauth.asyncio import (
    mark_factor_as_complete_in_session,
)
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multifactorauth.utils import (
    is_valid_first_factor,
    update_and_get_mfa_related_info_in_session,
)
from supertokens_python.recipe.multitenancy.asyncio import associate_user_to_tenant
from supertokens_python.recipe.session.asyncio import create_new_session, get_session
from supertokens_python.recipe.session.exceptions import UnauthorisedError
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types import (
    LoginMethod,
    RecipeUserId,
    User,
)
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError
from supertokens_python.types.base import AccountInfoInput
from supertokens_python.utils import log_debug_message

from .asyncio import get_user

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.types.base import WebauthnInfoInput


class OkResponse:
    status: Literal["OK"]
    valid_factor_ids: List[str]
    is_first_factor: bool

    def __init__(self, valid_factor_ids: List[str], is_first_factor: bool):
        self.status = "OK"
        self.valid_factor_ids = valid_factor_ids
        self.is_first_factor = is_first_factor


class SignUpNotAllowedResponse:
    status: Literal["SIGN_UP_NOT_ALLOWED"] = "SIGN_UP_NOT_ALLOWED"


class SignInNotAllowedResponse:
    status: Literal["SIGN_IN_NOT_ALLOWED"] = "SIGN_IN_NOT_ALLOWED"


async def pre_auth_checks(
    authenticating_account_info: AccountInfoWithRecipeId,
    authenticating_user: Union[User, None],
    tenant_id: str,
    factor_ids: List[str],
    is_sign_up: bool,
    is_verified: bool,
    sign_in_verifies_login_method: bool,
    skip_session_user_update_in_core: bool,
    session: Union[SessionContainer, None],
    should_try_linking_with_session_user: Union[bool, None],
    user_context: Dict[str, Any],
) -> Union[
    OkResponse,
    SignUpNotAllowedResponse,
    SignInNotAllowedResponse,
    LinkingToSessionUserFailedError,
]:
    valid_factor_ids: List[str] = []

    if len(factor_ids) == 0:
        raise Exception(
            "This should never happen: empty factorIds array passed to preSignInChecks"
        )

    log_debug_message("preAuthChecks checking auth types")
    auth_type_info = await check_auth_type_and_linking_status(
        session,
        should_try_linking_with_session_user,
        authenticating_account_info,
        authenticating_user,
        skip_session_user_update_in_core,
        user_context,
    )
    if auth_type_info.status != "OK":
        log_debug_message(
            f"preAuthChecks returning {auth_type_info.status} from checkAuthType results"
        )
        return auth_type_info

    if auth_type_info.is_first_factor:
        log_debug_message("preAuthChecks getting valid first factors")
        valid_first_factors = (
            await filter_out_invalid_first_factors_or_throw_if_all_are_invalid(
                factor_ids, tenant_id, session is not None, user_context
            )
        )
        valid_factor_ids = valid_first_factors
    else:
        assert isinstance(
            auth_type_info,
            (OkSecondFactorNotLinkedResponse, OkSecondFactorLinkedResponse),
        )
        assert session is not None
        log_debug_message("preAuthChecks getting valid secondary factors")
        valid_factor_ids = (
            await filter_out_invalid_second_factors_or_throw_if_all_are_invalid(
                factor_ids,
                auth_type_info.input_user_already_linked_to_session_user,
                auth_type_info.session_user,
                session,
                user_context,
            )
        )

    if not is_sign_up and authenticating_user is None:
        raise Exception(
            "This should never happen: preAuthChecks called with isSignUp: false, authenticatingUser: None"
        )

    if is_sign_up:
        verified_in_session_user = not isinstance(
            auth_type_info, OkFirstFactorResponse
        ) and any(
            lm.verified
            and (
                lm.has_same_email_as(authenticating_account_info.email)
                or lm.has_same_phone_number_as(authenticating_account_info.phone_number)
            )
            for lm in auth_type_info.session_user.login_methods
        )

        log_debug_message("preAuthChecks checking if the user is allowed to sign up")
        if not await AccountLinkingRecipe.get_instance().is_sign_up_allowed(
            new_user=authenticating_account_info,
            is_verified=is_verified
            or sign_in_verifies_login_method
            or verified_in_session_user,
            tenant_id=tenant_id,
            session=session,
            user_context=user_context,
        ):
            return SignUpNotAllowedResponse()
    elif authenticating_user is not None:
        log_debug_message("preAuthChecks checking if the user is allowed to sign in")
        if not await AccountLinkingRecipe.get_instance().is_sign_in_allowed(
            user=authenticating_user,
            account_info=authenticating_account_info,
            sign_in_verifies_login_method=sign_in_verifies_login_method,
            tenant_id=tenant_id,
            session=session,
            user_context=user_context,
        ):
            return SignInNotAllowedResponse()

    log_debug_message("preAuthChecks returning OK")
    return OkResponse(
        valid_factor_ids=valid_factor_ids,
        is_first_factor=auth_type_info.is_first_factor,
    )


class PostAuthChecksOkResponse:
    status: Literal["OK"]
    session: SessionContainer
    user: User

    def __init__(self, status: Literal["OK"], session: SessionContainer, user: User):
        self.status = status
        self.session = session
        self.user = user


class PostAuthChecksSignInNotAllowedResponse:
    status: Literal["SIGN_IN_NOT_ALLOWED"]


async def post_auth_checks(
    authenticated_user: User,
    recipe_user_id: RecipeUserId,
    is_sign_up: bool,
    factor_id: str,
    session: Union[SessionContainer, None],
    tenant_id: str,
    user_context: Dict[str, Any],
    request: BaseRequest,
) -> Union[PostAuthChecksOkResponse, PostAuthChecksSignInNotAllowedResponse]:
    log_debug_message(
        f"postAuthChecks called {'with' if session is not None else 'without'} a session to "
        f"{'sign up' if is_sign_up else 'sign in'} with {factor_id}"
    )

    mfa_instance = MultiFactorAuthRecipe.get_instance()

    resp_session = session
    if session is not None:
        authenticated_user_linked_to_session_user = any(
            lm.recipe_user_id.get_as_string()
            == session.get_recipe_user_id(user_context).get_as_string()
            for lm in authenticated_user.login_methods
        )
        if authenticated_user_linked_to_session_user:
            log_debug_message("postAuthChecks session and input user got linked")
            if mfa_instance is not None:
                log_debug_message("postAuthChecks marking factor as completed")
                # if the authenticating user is linked to the current session user (it means that the factor got set up or completed),
                # we mark it as completed in the session.
                assert resp_session is not None
                await mark_factor_as_complete_in_session(
                    resp_session, factor_id, user_context
                )
        else:
            log_debug_message("postAuthChecks checking overwriteSessionDuringSignInUp")
            # If the new user wasn't linked to the current one, we check the config and overwrite the session if required
            # Note: we could also get here if MFA is enabled, but the app didn't want to link the user to the session user.
            # This is intentional, since the MFA and overwriteSessionDuringSignInUp configs should work independently.
            resp_session = await create_new_session(
                request, tenant_id, recipe_user_id, {}, {}, user_context
            )
            if mfa_instance is not None:
                await mark_factor_as_complete_in_session(
                    resp_session, factor_id, user_context
                )
    else:
        log_debug_message("postAuthChecks creating session for first factor sign in/up")
        # If there is no input session, we do not need to do anything other checks and create a new session
        resp_session = await create_new_session(
            request, tenant_id, recipe_user_id, {}, {}, user_context
        )

        # Here we can always mark the factor as completed, since we just created the session
        if mfa_instance is not None:
            await mark_factor_as_complete_in_session(
                resp_session, factor_id, user_context
            )

    assert resp_session is not None
    return PostAuthChecksOkResponse(
        status="OK", session=resp_session, user=authenticated_user
    )


class AuthenticatingUserInfo:
    def __init__(self, user: User, login_method: Union[LoginMethod, None]):
        self.user = user
        self.login_method = login_method


async def get_authenticating_user_and_add_to_current_tenant_if_required(
    recipe_id: str,
    email: Optional[str],
    phone_number: Optional[str],
    third_party: Optional[ThirdPartyInfo],
    tenant_id: str,
    session: Optional[SessionContainer],
    check_credentials_on_tenant: Callable[[str], Awaitable[bool]],
    user_context: Dict[str, Any],
    webauthn: Optional["WebauthnInfoInput"] = None,
) -> Optional[AuthenticatingUserInfo]:
    i = 0
    while i < 300:
        account_info = {
            "email": email,
            "phoneNumber": phone_number,
            "thirdParty": third_party,
        }
        log_debug_message(
            f"getAuthenticatingUserAndAddToCurrentTenantIfRequired called with {account_info}"
        )
        existing_users = await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
            tenant_id=tenant_id,
            account_info=AccountInfoInput(
                email=email,
                phone_number=phone_number,
                third_party=third_party,
                webauthn=webauthn,
            ),
            do_union_of_account_info=True,
            user_context=user_context,
        )
        log_debug_message(
            f"getAuthenticatingUserAndAddToCurrentTenantIfRequired got {len(existing_users)} users from the core resp"
        )
        users_with_matching_login_methods = [
            AuthenticatingUserInfo(
                user=user,
                login_method=next(
                    (
                        lm
                        for lm in user.login_methods
                        if lm.recipe_id == recipe_id
                        and (
                            (email is not None and lm.has_same_email_as(email))
                            or lm.has_same_phone_number_as(phone_number)
                            or lm.has_same_third_party_info_as(third_party)
                            or lm.has_same_webauthn_info_as(webauthn)
                        )
                    ),
                    None,
                ),
            )
            for user in existing_users
        ]
        users_with_matching_login_methods = [
            u for u in users_with_matching_login_methods if u.login_method is not None
        ]
        log_debug_message(
            f"getAuthenticatingUserAndAddToCurrentTenantIfRequired got {len(users_with_matching_login_methods)} users with matching login methods"
        )
        if len(users_with_matching_login_methods) > 1:
            raise Exception(
                "You have found a bug. Please report it on https://github.com/supertokens/supertokens-node/issues"
            )
        authenticating_user = (
            AuthenticatingUserInfo(
                users_with_matching_login_methods[0].user,
                users_with_matching_login_methods[0].login_method,
            )
            if users_with_matching_login_methods
            else None
        )

        if authenticating_user is None and session is not None:
            log_debug_message(
                "getAuthenticatingUserAndAddToCurrentTenantIfRequired checking session user"
            )
            session_user = await get_user(
                session.get_user_id(user_context), user_context
            )
            if session_user is None:
                raise UnauthorisedError(
                    "Session user not found",
                )

            if not session_user.is_primary_user:
                log_debug_message(
                    "getAuthenticatingUserAndAddToCurrentTenantIfRequired session user is non-primary so returning early without checking other tenants"
                )
                return None

            matching_login_methods_from_session_user = [
                lm
                for lm in session_user.login_methods
                if lm.recipe_id == recipe_id
                and (
                    lm.has_same_email_as(email)
                    or lm.has_same_phone_number_as(phone_number)
                    or lm.has_same_third_party_info_as(third_party)
                )
            ]
            log_debug_message(
                f"getAuthenticatingUserAndAddToCurrentTenantIfRequired session has {len(matching_login_methods_from_session_user)} matching login methods"
            )

            if any(
                tenant_id in lm.tenant_ids
                for lm in matching_login_methods_from_session_user
            ):
                log_debug_message(
                    f"getAuthenticatingUserAndAddToCurrentTenantIfRequired session has {len(matching_login_methods_from_session_user)} matching login methods"
                )
                return AuthenticatingUserInfo(
                    user=session_user,
                    login_method=next(
                        lm
                        for lm in matching_login_methods_from_session_user
                        if tenant_id in lm.tenant_ids
                    ),
                )

            go_to_retry = False
            for lm in matching_login_methods_from_session_user:
                log_debug_message(
                    f"getAuthenticatingUserAndAddToCurrentTenantIfRequired session checking credentials on {lm.tenant_ids[0]}"
                )
                if await check_credentials_on_tenant(lm.tenant_ids[0]):
                    log_debug_message(
                        f"getAuthenticatingUserAndAddToCurrentTenantIfRequired associating user from {lm.tenant_ids[0]} with current tenant"
                    )
                    associate_res = await associate_user_to_tenant(
                        tenant_id, lm.recipe_user_id, user_context
                    )
                    log_debug_message(
                        f"getAuthenticatingUserAndAddToCurrentTenantIfRequired associating returned {associate_res.status}"
                    )
                    if associate_res.status == "OK":
                        lm.tenant_ids.append(tenant_id)
                        return AuthenticatingUserInfo(
                            user=session_user, login_method=lm
                        )
                    if associate_res.status in [
                        "UNKNOWN_USER_ID_ERROR",
                        "EMAIL_ALREADY_EXISTS_ERROR",
                        "PHONE_NUMBER_ALREADY_EXISTS_ERROR",
                        "THIRD_PARTY_USER_ALREADY_EXISTS_ERROR",
                    ]:
                        go_to_retry = True
                        break
                    if associate_res.status == "ASSOCIATION_NOT_ALLOWED_ERROR":
                        raise UnauthorisedError(
                            "Session user not associated with the session tenant"
                        )
            if go_to_retry:
                log_debug_message(
                    "getAuthenticatingUserAndAddToCurrentTenantIfRequired retrying"
                )
                i += 1
                continue
        return authenticating_user
    raise Exception(
        "This should never happen: ran out of retries for getAuthenticatingUserAndAddToCurrentTenantIfRequired"
    )


class OkFirstFactorResponse:
    status: Literal["OK"] = "OK"
    is_first_factor: Literal[True] = True


class OkSecondFactorLinkedResponse:
    status: Literal["OK"] = "OK"
    is_first_factor: Literal[False] = False
    input_user_already_linked_to_session_user: Literal[True] = True
    session_user: User

    def __init__(self, session_user: User):
        self.session_user = session_user


class OkSecondFactorNotLinkedResponse:
    status: Literal["OK"] = "OK"
    is_first_factor: Literal[False] = False
    input_user_already_linked_to_session_user: Literal[False] = False
    session_user: User
    linking_to_session_user_requires_verification: bool

    def __init__(
        self,
        session_user: User,
        linking_to_session_user_requires_verification: bool,
    ):
        self.session_user = session_user
        self.linking_to_session_user_requires_verification = (
            linking_to_session_user_requires_verification
        )


async def check_auth_type_and_linking_status(
    session: Union[SessionContainer, None],
    should_try_linking_with_session_user: Union[bool, None],
    account_info: AccountInfoWithRecipeId,
    input_user: Union[User, None],
    skip_session_user_update_in_core: bool,
    user_context: Dict[str, Any],
) -> Union[
    OkFirstFactorResponse,
    OkSecondFactorLinkedResponse,
    OkSecondFactorNotLinkedResponse,
    LinkingToSessionUserFailedError,
]:
    log_debug_message("check_auth_type_and_linking_status called")
    session_user: Union[User, None] = None
    if session is None:
        if should_try_linking_with_session_user is True:
            raise UnauthorisedError(
                "Session not found but shouldTryLinkingWithSessionUser is true"
            )
        log_debug_message(
            "check_auth_type_and_linking_status returning first factor because there is no session"
        )
        return OkFirstFactorResponse()
    else:
        if should_try_linking_with_session_user is False:
            # In our normal flows this should never happen - but some user overrides might do this.
            # Anyway, since should_try_linking_with_session_user explicitly set to false, it's safe to consider this a first factor
            log_debug_message(
                "check_auth_type_and_linking_status returning first factor because should_try_linking_with_session_user is False"
            )
            return OkFirstFactorResponse()
        if not recipe_init_defined_should_do_automatic_account_linking():
            if should_try_linking_with_session_user is True:
                raise Exception(
                    "Please initialise the account linking recipe and define should_do_automatic_account_linking to enable MFA"
                )
            else:
                if MultiFactorAuthRecipe.get_instance() is not None:
                    raise Exception(
                        "Please initialise the account linking recipe and define should_do_automatic_account_linking to enable MFA"
                    )
                else:
                    return OkFirstFactorResponse()

        if input_user is not None and input_user.id == session.get_user_id():
            log_debug_message(
                "check_auth_type_and_linking_status returning secondary factor, session and input user are the same"
            )
            return OkSecondFactorLinkedResponse(
                session_user=input_user,
            )

        log_debug_message(
            f"check_auth_type_and_linking_status loading session user, {input_user.id if input_user else None} === {session.get_user_id()}"
        )
        session_user_result = await try_and_make_session_user_into_a_primary_user(
            session, skip_session_user_update_in_core, user_context
        )
        if session_user_result.status == "SHOULD_AUTOMATICALLY_LINK_FALSE":
            if should_try_linking_with_session_user is True:
                raise BadInputError(
                    "shouldDoAutomaticAccountLinking returned false when making the session user primary but shouldTryLinkingWithSessionUser is true"
                )
            return OkFirstFactorResponse()
        elif (
            session_user_result.status
            == "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ):
            return LinkingToSessionUserFailedError(
                reason="SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
            )

        session_user = session_user_result.user

        should_link = await AccountLinkingRecipe.get_instance().config.should_do_automatic_account_linking(
            AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                account_info
            ),
            session_user,
            session,
            session.get_tenant_id(),
            user_context,
        )
        log_debug_message(
            f"check_auth_type_and_linking_status session user <-> input user should_do_automatic_account_linking returned {should_link}"
        )

        if isinstance(should_link, ShouldNotAutomaticallyLink):
            if should_try_linking_with_session_user is True:
                raise BadInputError(
                    "shouldDoAutomaticAccountLinking returned false when making the session user primary but shouldTryLinkingWithSessionUser is true"
                )
            return OkFirstFactorResponse()
        else:
            return OkSecondFactorNotLinkedResponse(
                session_user=session_user,
                linking_to_session_user_requires_verification=should_link.should_require_verification,
            )


class OkResponse2:
    status: Literal["OK"]
    user: User

    def __init__(self, user: User):
        self.status = "OK"
        self.user: User = user


async def link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
    tenant_id: str,
    input_user: User,
    recipe_user_id: RecipeUserId,
    session: Union[SessionContainer, None],
    should_try_linking_with_session_user: Union[bool, None],
    user_context: Dict[str, Any],
) -> Union[
    OkResponse2,
    LinkingToSessionUserFailedError,
]:
    log_debug_message(
        "link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info called"
    )

    async def retry():
        log_debug_message(
            "link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info retrying...."
        )
        return await link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
            tenant_id=tenant_id,
            input_user=input_user,
            session=session,
            recipe_user_id=recipe_user_id,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
            user_context=user_context,
        )

    auth_login_method = next(
        (
            lm
            for lm in input_user.login_methods
            if lm.recipe_user_id.get_as_string() == recipe_user_id.get_as_string()
        ),
        None,
    )
    if auth_login_method is None:
        raise Exception(
            "This should never happen: the recipe_user_id and user is inconsistent in create_primary_user_id_or_link_by_account_info params"
        )

    auth_type_res = await check_auth_type_and_linking_status(
        session,
        should_try_linking_with_session_user,
        AccountInfoWithRecipeId(
            recipe_id=auth_login_method.recipe_id,
            email=auth_login_method.email,
            phone_number=auth_login_method.phone_number,
            third_party=auth_login_method.third_party,
        ),
        input_user,
        False,
        user_context,
    )

    if not isinstance(
        auth_type_res,
        (
            OkFirstFactorResponse,
            OkSecondFactorLinkedResponse,
            OkSecondFactorNotLinkedResponse,
        ),
    ):
        return LinkingToSessionUserFailedError(reason=auth_type_res.reason)

    if isinstance(auth_type_res, OkFirstFactorResponse):
        if not recipe_init_defined_should_do_automatic_account_linking():
            log_debug_message(
                "link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info skipping link by account info because this is a first factor auth and the app hasn't defined should_do_automatic_account_linking"
            )
            return OkResponse2(user=input_user)
        log_debug_message(
            "link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info trying to link by account info because this is a first factor auth"
        )
        link_res = await AccountLinkingRecipe.get_instance().try_linking_by_account_info_or_create_primary_user(
            input_user=input_user,
            session=session,
            tenant_id=tenant_id,
            user_context=user_context,
        )
        if link_res.status == "OK":
            assert link_res.user is not None
            return OkResponse2(user=link_res.user)
        if link_res.status == "NO_LINK":
            return OkResponse2(user=input_user)
        return await retry()

    if isinstance(auth_type_res, OkSecondFactorLinkedResponse):
        return OkResponse2(user=auth_type_res.session_user)

    log_debug_message(
        "link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info trying to link by session info"
    )
    session_linking_res = await try_linking_by_session(
        session_user=auth_type_res.session_user,
        authenticated_user=input_user,
        auth_login_method=auth_login_method,
        linking_to_session_user_requires_verification=auth_type_res.linking_to_session_user_requires_verification,
        user_context=user_context,
    )
    if isinstance(session_linking_res, LinkingToSessionUserFailedError):
        if session_linking_res.reason == "INPUT_USER_IS_NOT_A_PRIMARY_USER":
            return await retry()
        else:
            return session_linking_res
    else:
        return session_linking_res


class ShouldAutomaticallyLinkFalseResponse:
    status: Literal["SHOULD_AUTOMATICALLY_LINK_FALSE"]

    def __init__(self):
        self.status = "SHOULD_AUTOMATICALLY_LINK_FALSE"


class AccountInfoAlreadyAssociatedResponse:
    status: Literal[
        "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
    ]

    def __init__(self):
        self.status = (
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        )


async def try_and_make_session_user_into_a_primary_user(
    session: SessionContainer,
    skip_session_user_update_in_core: bool,
    user_context: Dict[str, Any],
) -> Union[
    OkResponse2,
    ShouldAutomaticallyLinkFalseResponse,
    AccountInfoAlreadyAssociatedResponse,
]:
    log_debug_message("try_and_make_session_user_into_a_primary_user called")
    session_user = await get_user(session.get_user_id(), user_context)
    if session_user is None:
        raise UnauthorisedError("Session user not found")

    if session_user.is_primary_user:
        log_debug_message(
            "try_and_make_session_user_into_a_primary_user session user already primary"
        )
        return OkResponse2(user=session_user)
    else:
        log_debug_message(
            "try_and_make_session_user_into_a_primary_user not primary user yet"
        )

        account_linking_instance = AccountLinkingRecipe.get_instance()
        should_do_account_linking = (
            await account_linking_instance.config.should_do_automatic_account_linking(
                AccountInfoWithRecipeIdAndUserId.from_account_info_or_login_method(
                    session_user.login_methods[0]
                ),
                None,
                session,
                session.get_tenant_id(),
                user_context,
            )
        )
        log_debug_message(
            f"try_and_make_session_user_into_a_primary_user should_do_account_linking: {should_do_account_linking}"
        )

        if isinstance(should_do_account_linking, ShouldAutomaticallyLink):
            if skip_session_user_update_in_core:
                return OkResponse2(user=session_user)
            if (
                should_do_account_linking.should_require_verification
                and not session_user.login_methods[0].verified
            ):
                if (
                    await session.get_claim_value(EmailVerificationClaim, user_context)
                ) is not False:
                    log_debug_message(
                        "try_and_make_session_user_into_a_primary_user updating emailverification status in session"
                    )
                    await session.set_claim_value(
                        EmailVerificationClaim, False, user_context
                    )
                log_debug_message(
                    "try_and_make_session_user_into_a_primary_user throwing validation error"
                )
                await session.assert_claims(
                    [EmailVerificationClaim.validators.is_verified()], user_context
                )
                raise Exception(
                    "This should never happen: email verification claim validator passed after setting value to false"
                )
            create_primary_user_res = await account_linking_instance.recipe_implementation.create_primary_user(
                recipe_user_id=session_user.login_methods[0].recipe_user_id,
                user_context=user_context,
            )
            log_debug_message(
                f"try_and_make_session_user_into_a_primary_user create_primary_user returned {create_primary_user_res.status}"
            )
            if (
                create_primary_user_res.status
                == "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
            ):
                raise UnauthorisedError("Session user not found")
            elif create_primary_user_res.status == "OK":
                return OkResponse2(user=create_primary_user_res.user)
            else:
                return AccountInfoAlreadyAssociatedResponse()
        else:
            return ShouldAutomaticallyLinkFalseResponse()


async def try_linking_by_session(
    linking_to_session_user_requires_verification: bool,
    auth_login_method: LoginMethod,
    authenticated_user: User,
    session_user: User,
    user_context: Dict[str, Any],
) -> Union[
    OkResponse2,
    LinkingToSessionUserFailedError,
]:
    log_debug_message("tryLinkingBySession called")

    session_user_has_verified_account_info = any(
        (
            lm.has_same_email_as(auth_login_method.email)
            or lm.has_same_phone_number_as(auth_login_method.phone_number)
        )
        and lm.verified
        for lm in session_user.login_methods
    )

    can_link_based_on_verification = (
        not linking_to_session_user_requires_verification
        or auth_login_method.verified
        or session_user_has_verified_account_info
    )

    if not can_link_based_on_verification:
        return LinkingToSessionUserFailedError(reason="EMAIL_VERIFICATION_REQUIRED")

    link_accounts_result = (
        await AccountLinkingRecipe.get_instance().recipe_implementation.link_accounts(
            recipe_user_id=authenticated_user.login_methods[0].recipe_user_id,
            primary_user_id=session_user.id,
            user_context=user_context,
        )
    )

    if link_accounts_result.status == "OK":
        log_debug_message(
            "tryLinkingBySession successfully linked input user to session user"
        )
        return OkResponse2(user=link_accounts_result.user)
    elif (
        link_accounts_result.status
        == "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
    ):
        log_debug_message(
            "tryLinkingBySession linking to session user failed because of a race condition - input user linked to another user"
        )
        return LinkingToSessionUserFailedError(
            reason="RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        )
    elif link_accounts_result.status == "INPUT_USER_IS_NOT_A_PRIMARY_USER":
        log_debug_message(
            "tryLinkingBySession linking to session user failed because of a race condition - INPUT_USER_IS_NOT_A_PRIMARY_USER, should retry"
        )
        return LinkingToSessionUserFailedError(
            reason="INPUT_USER_IS_NOT_A_PRIMARY_USER"
        )
    else:
        log_debug_message(
            "tryLinkingBySession linking to session user failed because of a race condition - input user has another primary user it can be linked to"
        )
        return LinkingToSessionUserFailedError(
            reason="ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        )


async def filter_out_invalid_first_factors_or_throw_if_all_are_invalid(
    factor_ids: List[str],
    tenant_id: str,
    has_session: bool,
    user_context: Dict[str, Any],
) -> List[str]:
    valid_factor_ids: List[str] = []
    for _id in factor_ids:
        valid_res = await is_valid_first_factor(tenant_id, _id, user_context)

        if valid_res == "TENANT_NOT_FOUND_ERROR":
            if has_session:
                raise UnauthorisedError("Tenant not found")
            else:
                raise Exception("Tenant not found error.")
        elif valid_res == "OK":
            valid_factor_ids.append(_id)

    if len(valid_factor_ids) == 0:
        if not has_session:
            raise UnauthorisedError(
                "A valid session is required to authenticate with secondary factors"
            )
        else:
            raise_bad_input_exception(
                "First factor sign in/up called for a non-first factor with an active session. This might indicate that you are trying to use this as a secondary factor, but disabled account linking."
            )

    return valid_factor_ids


async def filter_out_invalid_second_factors_or_throw_if_all_are_invalid(
    factor_ids: List[str],
    input_user_already_linked_to_session_user: bool,
    session_user: User,
    session: SessionContainer,
    user_context: Dict[str, Any],
) -> List[str]:
    log_debug_message(
        f"filter_out_invalid_second_factors_or_throw_if_all_are_invalid called for {', '.join(factor_ids)}"
    )

    mfa_instance = MultiFactorAuthRecipe.get_instance()
    if mfa_instance is not None:
        if not input_user_already_linked_to_session_user:
            factors_set_up_for_user_prom: Optional[List[str]] = None
            mfa_info_prom = None

            async def get_factors_set_up_for_user() -> List[str]:
                nonlocal factors_set_up_for_user_prom
                if factors_set_up_for_user_prom is None:
                    factors_set_up_for_user_prom = await mfa_instance.recipe_implementation.get_factors_setup_for_user(
                        user=session_user, user_context=user_context
                    )
                assert factors_set_up_for_user_prom is not None
                return factors_set_up_for_user_prom

            async def get_mfa_requirements_for_auth():
                nonlocal mfa_info_prom
                if mfa_info_prom is None:
                    mfa_info_prom = await update_and_get_mfa_related_info_in_session(
                        input_session=session,
                        user_context=user_context,
                    )
                return mfa_info_prom.mfa_requirements_for_auth

            log_debug_message(
                "filter_out_invalid_second_factors_or_throw_if_all_are_invalid checking if linking is allowed by the mfa recipe"
            )
            caught_setup_factor_error: Optional[Exception] = None
            valid_factor_ids: List[str] = []

            for _id in factor_ids:
                log_debug_message(
                    "filter_out_invalid_second_factors_or_throw_if_all_are_invalid checking assert_allowed_to_setup_factor_else_throw_invalid_claim_error"
                )
                try:
                    await mfa_instance.recipe_implementation.assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
                        factor_id=_id,
                        session=session,
                        factors_set_up_for_user=get_factors_set_up_for_user,
                        mfa_requirements_for_auth=get_mfa_requirements_for_auth,
                        user_context=user_context,
                    )
                    log_debug_message(
                        f"filter_out_invalid_second_factors_or_throw_if_all_are_invalid {id} valid because assert_allowed_to_setup_factor_else_throw_invalid_claim_error passed"
                    )
                    valid_factor_ids.append(_id)
                except Exception as err:
                    log_debug_message(
                        f"filter_out_invalid_second_factors_or_throw_if_all_are_invalid assert_allowed_to_setup_factor_else_throw_invalid_claim_error failed for {id}"
                    )
                    caught_setup_factor_error = err

            if len(valid_factor_ids) == 0:
                log_debug_message(
                    "filter_out_invalid_second_factors_or_throw_if_all_are_invalid rethrowing error from assert_allowed_to_setup_factor_else_throw_invalid_claim_error because we found no valid factors"
                )
                if caught_setup_factor_error is not None:
                    raise caught_setup_factor_error
                else:
                    raise Exception("Should never come here")

            return valid_factor_ids
        else:
            log_debug_message(
                "filter_out_invalid_second_factors_or_throw_if_all_are_invalid allowing all factors because it'll not create new link"
            )
            return factor_ids
    else:
        log_debug_message(
            "filter_out_invalid_second_factors_or_throw_if_all_are_invalid allowing all factors because MFA is not enabled"
        )
        return factor_ids


def is_fake_email(email: str) -> bool:
    return email.endswith("@stfakeemail.supertokens.com") or email.endswith(
        ".fakeemail.com"
    )  # .fakeemail.com for older users


async def load_session_in_auth_api_if_needed(
    request: BaseRequest,
    should_try_linking_with_session_user: Optional[bool],
    user_context: Dict[str, Any],
) -> Optional[SessionContainer]:
    if should_try_linking_with_session_user is not False:
        return await get_session(
            request,
            session_required=should_try_linking_with_session_user is True,
            override_global_claim_validators=lambda _, __, ___: [],
            user_context=user_context,
        )
    return None
