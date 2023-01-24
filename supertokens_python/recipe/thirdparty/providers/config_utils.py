from typing import List, Dict, Optional, Any

from ..provider import ProviderConfig, ProviderInput, Provider


async def merge_providers_from_core_and_static(
    tenant_id: Optional[str],
    provider_configs_from_core: List[ProviderConfig],
    provider_inputs_from_static: List[ProviderInput],
) -> List[ProviderInput]:
    raise NotImplementedError  # TODO


async def find_and_create_provider_instance(
    providers: List[ProviderInput],
    third_party_id: str,
    client_type: Optional[str],
    user_context: Dict[str, Any],
) -> Provider:
    raise NotImplementedError  # TODO
