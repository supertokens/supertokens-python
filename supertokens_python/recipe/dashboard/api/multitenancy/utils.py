from typing import List
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
