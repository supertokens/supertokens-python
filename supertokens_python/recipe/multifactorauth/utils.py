from typing import Dict, Optional, Union

from supertokens_python import get_user
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.multitenancy import Multitenancy
from supertokens_python.recipe.multitenancy.utils import is_valid_first_factor
from supertokens_python.recipe.session import Session, SessionContainer
from supertokens_python.recipe.session.exceptions import UnauthorisedError

from .multi_factor_auth_claim import MultiFactorAuthClaim
from .types import (
    MFARequirementList,
    NormalizedOverride,
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

    override: NormalizedOverride = {
        "functions": config.override["functions"]
        if config is not None
        and config.override is not None
        and config.override["functions"] is not None
        else lambda a, o: a,
        "apis": config.override["apis"]
        if config is not None
        and config.override is not None
        and config.override["apis"] is not None
        else lambda a, o: a,
    }

    return TypeNormalisedInput(
        first_factors=config.first_factors if config is not None else None,
        override=override,
    )


async def update_and_get_mfa_related_info_in_session(
    input: Union[dict[str, Union[UserId, str, dict]], dict[str, SessionContainer]],
    updated_factor_id: Optional[str] = None,
    user_context: dict = {},
) -> dict[str, Union[MFAClaimValue["c"], MFARequirementList, bool]]:
    session_recipe_user_id: UserId
    tenant_id: str
    access_token_payload: dict
    session_handle: str

    if "session" in input:
        session: SessionContainer = input["session"]
        session_recipe_user_id = session.get_recipe_user_id(user_context)
        tenant_id = session.get_tenant_id(user_context)
        access_token_payload = session.get_access_token_payload(user_context)
        session_handle = session.get_handle(user_context)
    else:
        session_recipe_user_id = input["session_recipe_user_id"]
        tenant_id = input["tenant_id"]
        access_token_payload = input["access_token_payload"]
        session_handle = access_token_payload["sessionHandle"]

    updated_claim_val = False
    mfa_claim_value = MultiFactorAuthClaim.get_value_from_payload(access_token_payload)

    if updated_factor_id:
        if mfa_claim_value is None:
            updated_claim_val = True
            mfa_claim_value = {
                "c": {updated_factor_id: int(time.time())},
                "v": True,  # updated later in the function
            }
        else:
            updated_claim_val = True
            mfa_claim_value["c"][updated_factor_id] = int(time.time())

    if mfa_claim_value is None:
        session_user = await get_user(str(session_recipe_user_id), user_context)
        if session_user is None:
            raise UnauthorisedError("Session user not found")

        session_info: Optional[
            SessionInformation
        ] = await Session.get_session_information(session_handle, user_context)

        if session_info is None:
            raise UnauthorisedError("Session not found")

        first_factor_time = session_info.time_created
        computed_first_factor_id_for_session: Optional[str] = None
        for login_method in session_user.login_methods:
            if (
                login_method.recipe_user_id.get_as_string()
                == session_recipe_user_id.get_as_string()
            ):
                if login_method.recipe_id == "emailpassword":
                    valid_res = await is_valid_first_factor(
                        tenant_id, FactorIds.EMAILPASSWORD, user_context
                    )
                    if valid_res.status == "TENANT_NOT_FOUND_ERROR":
                        raise UnauthorisedError("Tenant not found")
                    elif valid_res.status == "OK":
                        computed_first_factor_id_for_session = FactorIds.EMAILPASSWORD
                        break
                elif login_method.recipe_id == "thirdparty":
                    valid_res = await is_valid_first_factor(
                        tenant_id, FactorIds.THIRDPARTY, user_context
                    )
                    if valid_res.status == "TENANT_NOT_FOUND_ERROR":
                        raise UnauthorisedError("Tenant not found")
                    elif valid_res.status == "OK":
                        computed_first_factor_id_for_session = FactorIds.THIRDPARTY
                        break
                else:
                    factors_to_check = []
                    if login_method.email is not None:
                        factors_to_check.extend(
                            [FactorIds.LINK_EMAIL, FactorIds.OTP_EMAIL]
                        )
                    if login_method.phone_number is not None:
                        factors_to_check.extend(
                            [FactorIds.LINK_PHONE, FactorIds.OTP_PHONE]
                        )

                    for factor_id in factors_to_check:
                        valid_res = await is_valid_first_factor(
                            tenant_id, factor_id, user_context
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
        mfa_claim_value = {
            "c": {computed_first_factor_id_for_session: first_factor_time},
            "v": True,  # updated later in this function
        }

    completed_factors = mfa_claim_value["c"]

    user_prom: Optional[User] = None

    async def user_getter():
        nonlocal user_prom
        if user_prom is None:
            session_user = await get_user(str(session_recipe_user_id), user_context)
            if session_user is None:
                raise UnauthorisedError("Session user not found")
            user_prom = session_user
        return user_prom

    mfa_requirements_for_auth = await Recipe.get_instance().recipe_implementation.get_mfa_requirements_for_auth(
        {
            "access_token_payload": access_token_payload,
            "tenant_id": tenant_id,
            "user": user_getter,
            "factors_setup_for_user": lambda: user_getter().then(
                lambda user: Recipe.get_instance().recipe_implementation.get_factors_setup_for_user(
                    user=user, user_context=user_context
                )
            ),
            "required_secondary_factors_for_user": lambda: user_getter().then(
                lambda session_user: Recipe.get_instance().recipe_implementation.get_required_secondary_factors_for_user(
                    user_id=session_user.user_id, user_context=user_context
                )
            ),
            "required_secondary_factors_for_tenant": lambda: Multitenancy.get_tenant(
                tenant_id, user_context
            ).then(
                lambda tenant_info: tenant_info.required_secondary_factors
                if tenant_info is not None
                else []
            ),
            "completed_factors": completed_factors,
            "user_context": user_context,
        }
    )

    are_auth_reqs_complete = (
        len(
            MultiFactorAuthClaim.get_next_set_of_unsatisfied_factors(
                completed_factors, mfa_requirements_for_auth
            ).factor_ids
        )
        == 0
    )
    if mfa_claim_value["v"] != are_auth_reqs_complete:
        updated_claim_val = True
        mfa_claim_value["v"] = are_auth_reqs_complete

    if "session" in input and updated_claim_val:
        await input["session"].set_claim_value(
            MultiFactorAuthClaim, mfa_claim_value, user_context
        )

    return {
        "completed_factors": completed_factors,
        "mfa_requirements_for_auth": mfa_requirements_for_auth,
        "is_mfa_requirements_for_auth_satisfied": mfa_claim_value["v"],
    }
