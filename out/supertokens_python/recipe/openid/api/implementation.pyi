from supertokens_python.recipe.openid.interfaces import APIInterface as APIInterface, APIOptions as APIOptions, OpenIdDiscoveryConfigurationGetResponse as OpenIdDiscoveryConfigurationGetResponse
from typing import Any, Dict

class APIImplementation(APIInterface):
    async def open_id_discovery_configuration_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> OpenIdDiscoveryConfigurationGetResponse: ...
