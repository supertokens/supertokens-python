from __future__ import annotations

from typing import Any, Dict, List

from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.multitenancy.types import ValidFirstFactorResponse
from supertokens_python.utils import log_debug_message


async def is_valid_first_factor(
    tenant_id: str, factor_id: str, user_context: Dict[str, Any]
) -> ValidFirstFactorResponse:
    mt_recipe = MultitenancyRecipe.get_instance()
    if mt_recipe is None:
        raise Exception("Should never happen")

    tenant_info = await mt_recipe.recipe_implementation.get_tenant(
        tenant_id=tenant_id, user_context=user_context
    )
    if tenant_info is None:
        return ValidFirstFactorResponse(status="TENANT_NOT_FOUND_ERROR")

    tenant_config: TenantConfig = {
        k: v for k, v in tenant_info.items() if k != "status"
    }

    first_factors_from_mfa = mt_recipe.static_first_factors

    log_debug_message(
        f"is_valid_first_factor got {', '.join(tenant_config.get('first_factors', []))} from tenant config"
    )
    log_debug_message(f"is_valid_first_factor got {first_factors_from_mfa} from MFA")
    log_debug_message(
        f"is_valid_first_factor tenantconfig enables: {[k for k, v in tenant_config.items() if isinstance(v, dict) and v.get('enabled')]}"
    )

    configured_first_factors: Union[List[str], None] = tenant_config.get(
        "first_factors", first_factors_from_mfa
    )

    if configured_first_factors is None:
        configured_first_factors = mt_recipe.all_available_first_factors

    if is_factor_configured_for_tenant(
        tenant_config=tenant_config,
        all_available_first_factors=mt_recipe.all_available_first_factors,
        first_factors=configured_first_factors,
        factor_id=factor_id,
    ):
        return ValidFirstFactorResponse(status="OK")

    return ValidFirstFactorResponse(status="INVALID_FIRST_FACTOR_ERROR")


def is_factor_configured_for_tenant(
    tenant_config: TenantConfig,
    all_available_first_factors: List[str],
    first_factors: List[str],
    factor_id: str,
) -> bool:
    configured_first_factors = [
        f
        for f in first_factors
        if f in all_available_first_factors or f not in FactorIds.__dict__.values()
    ]

    return factor_id in configured_first_factors
