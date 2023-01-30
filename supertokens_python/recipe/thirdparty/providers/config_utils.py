from typing import List, Dict, Optional, Any

from ..provider import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderConfigForClientType,
    ProviderInput,
    Provider,
)


def get_provider_config_for_client(
    config: ProviderConfig, client_config: ProviderClientConfig
) -> ProviderConfigForClientType:
    return ProviderConfigForClientType(
        client_id=client_config.client_id,
        client_secret=client_config.client_secret,
        scope=client_config.scope,
        force_pkce=client_config.force_pkce,
        additional_config=client_config.additional_config,
        authorization_endpoint=config.authorization_endpoint,
        authorization_endpoint_query_params=config.authorization_endpoint_query_params,
        token_endpoint=config.token_endpoint,
        token_endpoint_body_params=config.token_endpoint_body_params,
        user_info_endpoint=config.user_info_endpoint,
        user_info_endpoint_query_params=config.user_info_endpoint_query_params,
        user_info_endpoint_headers=config.user_info_endpoint_headers,
        user_info_map=config.user_info_map,
        jwks_uri=config.jwks_uri,
        oidc_discovery_endpoint=config.oidc_discovery_endpoint,
        validate_id_token_payload=config.validate_id_token_payload,
        require_email=config.require_email,
        generate_fake_email=config.generate_fake_email,
        name=config.name,
        tenant_id=config.tenant_id,
    )


def merge_providers_from_core_and_static(
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
