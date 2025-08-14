from typing import List

from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.multifactorauth.utils import (
    is_factor_configured_for_tenant,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe


def get_normalised_first_factors_based_on_tenant_config_from_core_and_sdk_init(
    tenant_details_from_core: TenantConfig,
) -> List[str]:
    first_factors: List[str]

    mt_instance = MultitenancyRecipe.get_instance()

    if tenant_details_from_core.first_factors is not None:
        first_factors = (
            tenant_details_from_core.first_factors
        )  # highest priority, config from core
    elif mt_instance.static_first_factors is not None:
        first_factors = mt_instance.static_first_factors  # next priority, static config
    else:
        # Fallback to all available factors (de-duplicated)
        first_factors = list(set(mt_instance.all_available_first_factors))

    # we now filter out all available first factors by checking if they are valid because
    # we want to return the ones that can work. this would be based on what recipes are enabled
    # on the core and also first_factors configured in the core and supertokens.init
    # Also, this way, in the front end, the developer can just check for first_factors for
    # enabled recipes in all cases irrespective of whether they are using MFA or not
    valid_first_factors: List[str] = []
    for factor_id in first_factors:
        if is_factor_configured_for_tenant(
            all_available_first_factors=mt_instance.all_available_first_factors,
            first_factors=first_factors,
            factor_id=factor_id,
        ):
            valid_first_factors.append(factor_id)

    return valid_first_factors


def get_factor_not_available_message(
    factor_id: str, available_factors: List[str]
) -> str:
    recipe_name = factor_id_to_recipe(factor_id)
    if recipe_name != "Passwordless":
        return f"Please initialise {recipe_name} recipe to be able to use this login method"

    passwordless_factors = [
        FactorIds.LINK_EMAIL,
        FactorIds.LINK_PHONE,
        FactorIds.OTP_EMAIL,
        FactorIds.OTP_PHONE,
    ]
    passwordless_factors_not_available = [
        f for f in passwordless_factors if f not in available_factors
    ]

    if len(passwordless_factors_not_available) == 4:
        return (
            "Please initialise Passwordless recipe to be able to use this login method"
        )

    flow_type, contact_method = factor_id.split("-")
    return f"Please ensure that Passwordless recipe is initialised with contactMethod: {contact_method.upper()} and flowType: {'USER_INPUT_CODE' if flow_type == 'otp' else 'MAGIC_LINK'}"


def factor_id_to_recipe(factor_id: str) -> str:
    factor_id_to_recipe_map = {
        "emailpassword": "Emailpassword",
        "thirdparty": "ThirdParty",
        "otp-email": "Passwordless",
        "otp-phone": "Passwordless",
        "link-email": "Passwordless",
        "link-phone": "Passwordless",
        "totp": "Totp",
        "webauthn": "WebAuthn",
    }

    return factor_id_to_recipe_map.get(factor_id, "")


async def get_normalised_required_secondary_factors_based_on_tenant_config_from_core_and_sdk_init(
    tenant_details_from_core: TenantConfig,
) -> List[str]:
    mfa_instance = MultiFactorAuthRecipe.get_instance()

    if mfa_instance is None:
        return []

    secondary_factors = await mfa_instance.get_all_available_secondary_factor_ids(
        tenant_details_from_core
    )
    secondary_factors = [
        factor_id
        for factor_id in secondary_factors
        if factor_id in (tenant_details_from_core.required_secondary_factors or [])
    ]

    return secondary_factors
