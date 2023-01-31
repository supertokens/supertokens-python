from typing import Any, Dict, Optional
from .custom import GenericProvider, NewProvider
from ..provider import (
    Provider,
    ProviderConfigForClientType,
    ProviderInput,
    UserFields,
    UserInfoMap,
)


class ActiveDirectoryImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClientType:
        config = await super().get_config_for_client_type(client_type, user_context)
        if config.oidc_discovery_endpoint is None:
            if (
                config.additional_config is None
                or config.additional_config.get("directoryId") is None
            ):
                raise Exception(
                    "Please provide the directoryId in the additionalConfig of the Active Directory provider."
                )

            config.oidc_discovery_endpoint = f"https://login.microsoftonline.com/{config.additional_config.get('directoryId')}/v2.0/"

        if config.scope is None:
            config.scope = ["openid", "email"]

        # TODO later if required, client assertion impl

        return config


def ActiveDirectory(input: ProviderInput) -> Provider:
    if input.config.name is None:
        input.config.name = "Active Directory"

    if input.config.user_info_map is None:
        input.config.user_info_map = UserInfoMap(UserFields(), UserFields())

    if input.config.user_info_map.from_id_token_payload.user_id is None:
        input.config.user_info_map.from_id_token_payload.user_id = "sub"

    if input.config.user_info_map.from_id_token_payload.email is None:
        input.config.user_info_map.from_id_token_payload.email = "email"

    return NewProvider(input, ActiveDirectoryImpl)
