import asyncio
import time
from typing import Any, Awaitable, Dict, List, Optional

from supertokens_python.asyncio import get_user
from supertokens_python.recipe.multifactorauth.recipe import (
    MultiFactorAuthRecipe as Recipe,
)
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.multitenancy.asyncio import get_tenant
from supertokens_python.recipe.multitenancy.factors import is_valid_first_factor
from supertokens_python.recipe.session.asyncio import get_session_information
from supertokens_python.recipe.session.exceptions import UnauthorisedError
from supertokens_python.types import AccountLinkingUser

from .multi_factor_auth_claim import MultiFactorAuthClaim
from .types import (
    MFAClaimValue,
    MFARelatedInfoInSession,
    MFARequirementList,
    NormalizedOverride,
    SessionInput,
    SessionInputType,
    TypeInput,
    TypeNormalisedInput,
)


def validate_and_normalise_user_input(
    config: Optional[TypeInput],
) -> TypeNormalisedInput:
    if (
        config is not None
        and config.first_factors is not None
        and len(config.first_factors) == 0
    ):
        raise Exception("'first_factors' can be either None or a non-empty array")

    override: NormalizedOverride = NormalizedOverride(
        functions=config.override.functions
        if config is not None
        and config.override is not None
        and config.override.functions
        else lambda a: a,
        apis=config.override.apis
        if config is not None and config.override is not None and config.override.apis
        else lambda a: a,
    )

    return TypeNormalisedInput(
        first_factors=config.first_factors if config is not None else None,
        override=override,
    )


async def update_and_get_mfa_related_info_in_session(
    input: SessionInputType,
) -> MFARelatedInfoInSession:
    session_recipe_user_id: str
    tenant_id: str
    access_token_payload: Dict[str, Any]
    session_handle: str

    if isinstance(input, SessionInput):
        session_recipe_user_id = input.session.get_recipe_user_id(
            input.user_context
        ).get_as_string()
        tenant_id = input.session.get_tenant_id(input.user_context)
        access_token_payload = input.session.get_access_token_payload(
            input.user_context
        )
        session_handle = input.session.get_handle(input.user_context)
    else:
        session_recipe_user_id = input.session_recipe_user_id
        tenant_id = input.tenant_id
        access_token_payload = input.access_token_payload
        session_handle = access_token_payload["sessionHandle"]

    updated_claim_val = False
    mfa_claim_value = MultiFactorAuthClaim.get_value_from_payload(access_token_payload)

    if input.updated_factor_id is not None:
        if mfa_claim_value is None:
            updated_claim_val = True
            mfa_claim_value = MFAClaimValue(
                c={input.updated_factor_id: int(time.time()) * 1000}, v=True
            )
        else:
            updated_claim_val = True
            mfa_claim_value.c[input.updated_factor_id] = int(time.time()) * 1000

    if mfa_claim_value is None:
        # it should be fine to get the user multiple times since the caching will de-duplicate these requests
        session_user = await get_user(session_recipe_user_id, input.user_context)
        if session_user is None:
            raise UnauthorisedError("Session user not found")

        # This can happen with older session, because we did not add MFA claims previously.
        # We try to determine best possible factorId based on the session's recipe user id.

        session_info = await get_session_information(session_handle, input.user_context)
        if session_info is None:
            raise UnauthorisedError("Session not found")

        first_factor_time = session_info.time_created
        computed_first_factor_id_for_session: Optional[str] = None
        for login_method in session_user.login_methods:
            if login_method.recipe_user_id.get_as_string() == session_recipe_user_id:
                if login_method.recipe_id == "emailpassword":
                    valid_res = await is_valid_first_factor(
                        tenant_id, FactorIds.EMAILPASSWORD, input.user_context
                    )
                    if valid_res.status == "TENANT_NOT_FOUND_ERROR":
                        raise UnauthorisedError("Tenant not found")
                    elif valid_res.status == "OK":
                        computed_first_factor_id_for_session = FactorIds.EMAILPASSWORD
                        break
                elif login_method.recipe_id == "thirdparty":
                    valid_res = await is_valid_first_factor(
                        tenant_id, FactorIds.THIRDPARTY, input.user_context
                    )
                    if valid_res.status == "TENANT_NOT_FOUND_ERROR":
                        raise UnauthorisedError("Tenant not found")
                    elif valid_res.status == "OK":
                        computed_first_factor_id_for_session = FactorIds.THIRDPARTY
                        break
                else:
                    factors_to_check: List[str] = []
                    if login_method.email is not None:
                        factors_to_check.append(FactorIds.LINK_EMAIL)
                        factors_to_check.append(FactorIds.OTP_EMAIL)
                    if login_method.phone_number is not None:
                        factors_to_check.append(FactorIds.LINK_PHONE)
                        factors_to_check.append(FactorIds.OTP_PHONE)

                    for factor_id in factors_to_check:
                        valid_res = await is_valid_first_factor(
                            tenant_id, factor_id, input.user_context
                        )
                        if valid_res.status == "TENANT_NOT_FOUND_ERROR":
                            raise UnauthorisedError("Tenant not found")
                        elif valid_res.status == "OK":
                            computed_first_factor_id_for_session = factor_id
                            break

                    if computed_first_factor_id_for_session is not None:
                        break

        if computed_first_factor_id_for_session is None:
            raise UnauthorisedError("Incorrect login method used")

        updated_claim_val = True
        mfa_claim_value = MFAClaimValue(
            c={computed_first_factor_id_for_session: first_factor_time},
            v=True,  # updated later in this function
        )

    completed_factors = mfa_claim_value.c

    async def get_user_or_raise() -> AccountLinkingUser:
        user = await get_user(session_recipe_user_id, input.user_context)
        if user is None:
            raise UnauthorisedError("Session user not found")
        return user

    user_prom: Awaitable[AccountLinkingUser] = asyncio.create_task(get_user_or_raise())

    async def get_factors_setup_for_user() -> List[str]:
        user = await user_prom
        return await Recipe.get_instance_or_throw_error().recipe_implementation.get_factors_setup_for_user(
            user=user, user_context=input.user_context
        )

    async def get_required_secondary_factors_for_user() -> List[str]:
        user = await user_prom
        return await Recipe.get_instance_or_throw_error().recipe_implementation.get_required_secondary_factors_for_user(
            user_id=user.id, user_context=input.user_context
        )

    async def get_required_secondary_factors_for_tenant() -> List[str]:
        tenant_info = await get_tenant(tenant_id, input.user_context)
        return (
            tenant_info.required_secondary_factors
            if tenant_info and tenant_info.required_secondary_factors
            else []
        )

    mfa_requirements_for_auth: MFARequirementList = await Recipe.get_instance_or_throw_error().recipe_implementation.get_mfa_requirements_for_auth(
        tenant_id=tenant_id,
        access_token_payload=access_token_payload,
        completed_factors=completed_factors,
        user=user_prom,
        factors_set_up_for_user=asyncio.create_task(get_factors_setup_for_user()),
        required_secondary_factors_for_user=asyncio.create_task(
            get_required_secondary_factors_for_user()
        ),
        required_secondary_factors_for_tenant=asyncio.create_task(
            get_required_secondary_factors_for_tenant()
        ),
        user_context=input.user_context,
    )

    are_auth_reqs_complete = (
        len(
            MultiFactorAuthClaim.get_next_set_of_unsatisfied_factors(
                completed_factors, mfa_requirements_for_auth
            ).factor_ids
        )
        == 0
    )

    if mfa_claim_value.v != are_auth_reqs_complete:
        updated_claim_val = True
        mfa_claim_value.v = are_auth_reqs_complete

    if isinstance(input, SessionInput) and updated_claim_val:
        await input.session.set_claim_value(
            MultiFactorAuthClaim, mfa_claim_value, input.user_context
        )

    return MFARelatedInfoInSession(
        completed_factors=completed_factors,
        mfa_requirements_for_auth=mfa_requirements_for_auth,
        is_mfa_requirements_for_auth_satisfied=mfa_claim_value.v,
    )
