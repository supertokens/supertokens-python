from typing import List, Dict, Optional, Any

from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath
from .active_directory import ActiveDirectory
from .apple import Apple
from .bitbucket import Bitbucket
from .boxy_saml import BoxySAML
from .discord import Discord
from .facebook import Facebook
from .github import Github
from .gitlab import Gitlab
from .google_workspaces import GoogleWorkspaces
from .google import Google
from .linkedin import Linkedin
from .twitter import Twitter
from .okta import Okta
from .custom import NewProvider
from .utils import do_get_request

from ..provider import (
    ProviderConfig,
    ProviderConfigForClient,
    ProviderInput,
    Provider,
    UserFields,
    UserInfoMap,
)


def merge_config(
    config_from_static: ProviderConfig, config_from_core: ProviderConfig
) -> ProviderConfig:
    result = ProviderConfig(
        third_party_id=config_from_static.third_party_id,
        name=(
            config_from_static.name
            if config_from_core.name is None
            else config_from_core.name
        ),
        authorization_endpoint=(
            config_from_static.authorization_endpoint
            if config_from_core.authorization_endpoint is None
            else config_from_core.authorization_endpoint
        ),
        authorization_endpoint_query_params=(
            config_from_static.authorization_endpoint_query_params
            if config_from_core.authorization_endpoint_query_params is None
            else config_from_core.authorization_endpoint_query_params
        ),
        token_endpoint=(
            config_from_static.token_endpoint
            if config_from_core.token_endpoint is None
            else config_from_core.token_endpoint
        ),
        token_endpoint_body_params=(
            config_from_static.token_endpoint_body_params
            if config_from_core.token_endpoint_body_params is None
            else config_from_core.token_endpoint_body_params
        ),
        user_info_endpoint=(
            config_from_static.user_info_endpoint
            if config_from_core.user_info_endpoint is None
            else config_from_core.user_info_endpoint
        ),
        user_info_endpoint_headers=(
            config_from_static.user_info_endpoint_headers
            if config_from_core.user_info_endpoint_headers is None
            else config_from_core.user_info_endpoint_headers
        ),
        user_info_endpoint_query_params=(
            config_from_static.user_info_endpoint_query_params
            if config_from_core.user_info_endpoint_query_params is None
            else config_from_core.user_info_endpoint_query_params
        ),
        jwks_uri=(
            config_from_static.jwks_uri
            if config_from_core.jwks_uri is None
            else config_from_core.jwks_uri
        ),
        oidc_discovery_endpoint=(
            config_from_static.oidc_discovery_endpoint
            if config_from_core.oidc_discovery_endpoint is None
            else config_from_core.oidc_discovery_endpoint
        ),
        require_email=config_from_static.require_email,
        user_info_map=config_from_static.user_info_map,
        generate_fake_email=config_from_static.generate_fake_email,
        validate_id_token_payload=config_from_static.validate_id_token_payload,
        validate_access_token=config_from_static.validate_access_token,
    )

    if result.user_info_map is None:
        result.user_info_map = UserInfoMap(UserFields(), UserFields())

    if result.user_info_map.from_user_info_api is None:
        result.user_info_map.from_user_info_api = UserFields()
    if result.user_info_map.from_id_token_payload is None:
        result.user_info_map.from_id_token_payload = UserFields()

    if config_from_core.user_info_map is not None:
        if config_from_core.user_info_map.from_user_info_api is None:
            config_from_core.user_info_map.from_user_info_api = UserFields()
        if config_from_core.user_info_map.from_id_token_payload is None:
            config_from_core.user_info_map.from_id_token_payload = UserFields()

        if config_from_core.user_info_map.from_id_token_payload.user_id is not None:
            result.user_info_map.from_id_token_payload.user_id = (
                config_from_core.user_info_map.from_id_token_payload.user_id
            )
        if config_from_core.user_info_map.from_id_token_payload.email is not None:
            result.user_info_map.from_id_token_payload.email = (
                config_from_core.user_info_map.from_id_token_payload.email
            )
        if (
            config_from_core.user_info_map.from_id_token_payload.email_verified
            is not None
        ):
            result.user_info_map.from_id_token_payload.email_verified = (
                config_from_core.user_info_map.from_id_token_payload.email_verified
            )

        if config_from_core.user_info_map.from_user_info_api.user_id is not None:
            result.user_info_map.from_user_info_api.user_id = (
                config_from_core.user_info_map.from_user_info_api.user_id
            )
        if config_from_core.user_info_map.from_user_info_api.email is not None:
            result.user_info_map.from_user_info_api.email = (
                config_from_core.user_info_map.from_user_info_api.email
            )
        if config_from_core.user_info_map.from_user_info_api.email_verified is not None:
            result.user_info_map.from_user_info_api.email_verified = (
                config_from_core.user_info_map.from_user_info_api.email_verified
            )

    merged_clients = (config_from_static.clients or [])[:]  # Make a copy
    core_config_clients = config_from_core.clients or []

    for core_client in core_config_clients:
        found = False
        for idx, static_client in enumerate(merged_clients):
            if static_client.client_type == core_client.client_type:
                merged_clients[idx] = core_client
                found = True
                break

        if not found:
            merged_clients.append(core_client)

    result.clients = merged_clients

    return result


def merge_providers_from_core_and_static(
    provider_configs_from_core: List[ProviderConfig],
    provider_inputs_from_static: List[ProviderInput],
) -> List[ProviderInput]:
    merged_providers: List[ProviderInput] = []

    if len(provider_configs_from_core) == 0:
        for config in provider_inputs_from_static:
            merged_providers.append(config)
    else:
        for provider_config_from_core in provider_configs_from_core:
            merged_provider_input = ProviderInput(provider_config_from_core)

            for provider_input_from_static in provider_inputs_from_static:
                if (
                    provider_input_from_static.config.third_party_id
                    == provider_config_from_core.third_party_id
                ):
                    merged_provider_input.config = merge_config(
                        provider_input_from_static.config, provider_config_from_core
                    )
                    merged_provider_input.override = provider_input_from_static.override
                    break

            merged_providers.append(merged_provider_input)

    return merged_providers


def create_provider(provider_input: ProviderInput) -> Provider:
    if provider_input.config.third_party_id.startswith("active-directory"):
        return ActiveDirectory(provider_input)
    if provider_input.config.third_party_id.startswith("apple"):
        return Apple(provider_input)
    if provider_input.config.third_party_id.startswith("bitbucket"):
        return Bitbucket(provider_input)
    if provider_input.config.third_party_id.startswith("discord"):
        return Discord(provider_input)
    if provider_input.config.third_party_id.startswith("facebook"):
        return Facebook(provider_input)
    if provider_input.config.third_party_id.startswith("github"):
        return Github(provider_input)
    if provider_input.config.third_party_id.startswith("gitlab"):
        return Gitlab(provider_input)
    if provider_input.config.third_party_id.startswith("google-workspaces"):
        return GoogleWorkspaces(provider_input)
    if provider_input.config.third_party_id.startswith("google"):
        return Google(provider_input)
    if provider_input.config.third_party_id.startswith("okta"):
        return Okta(provider_input)
    if provider_input.config.third_party_id.startswith("linkedin"):
        return Linkedin(provider_input)
    if provider_input.config.third_party_id.startswith("twitter"):
        return Twitter(provider_input)
    if provider_input.config.third_party_id.startswith("boxy-saml"):
        return BoxySAML(provider_input)

    return NewProvider(provider_input)


OIDC_INFO_MAP: Dict[str, Any] = {}


async def get_oidc_discovery_info(issuer: str):
    if issuer in OIDC_INFO_MAP:
        return OIDC_INFO_MAP[issuer]

    ndomain = NormalisedURLDomain(issuer)
    npath = NormalisedURLPath(issuer)
    openid_config_path = NormalisedURLPath("/.well-known/openid-configuration")

    npath = npath.append(openid_config_path)

    oidc_info = await do_get_request(
        ndomain.get_as_string_dangerous() + npath.get_as_string_dangerous()
    )
    OIDC_INFO_MAP[issuer] = oidc_info

    return oidc_info


async def discover_oidc_endpoints(
    config: ProviderConfigForClient,
) -> ProviderConfigForClient:
    if config.oidc_discovery_endpoint is None:
        return config

    oidc_info = await get_oidc_discovery_info(config.oidc_discovery_endpoint)
    if (
        oidc_info.get("authorization_endpoint") is not None
        and config.authorization_endpoint is None
    ):
        config.authorization_endpoint = oidc_info["authorization_endpoint"]

    if oidc_info.get("token_endpoint") is not None and config.token_endpoint is None:
        config.token_endpoint = oidc_info["token_endpoint"]

    if (
        oidc_info.get("userinfo_endpoint") is not None
        and config.user_info_endpoint is None
    ):
        config.user_info_endpoint = oidc_info["userinfo_endpoint"]

    if oidc_info.get("jwks_uri") is not None and config.jwks_uri is None:
        config.jwks_uri = oidc_info["jwks_uri"]

    return config


async def fetch_and_set_config(
    provider_instance: Provider,
    client_type: Optional[str],
    user_context: Dict[str, Any],
):
    config = await provider_instance.get_config_for_client_type(
        client_type, user_context
    )
    config = await discover_oidc_endpoints(config)
    provider_instance.config = config


async def find_and_create_provider_instance(
    providers: List[ProviderInput],
    third_party_id: str,
    client_type: Optional[str],
    user_context: Dict[str, Any],
) -> Optional[Provider]:
    for provider_input in providers:
        if provider_input.config.third_party_id == third_party_id:
            provider_instance = create_provider(provider_input)
            await fetch_and_set_config(provider_instance, client_type, user_context)
            return provider_instance

    return None
