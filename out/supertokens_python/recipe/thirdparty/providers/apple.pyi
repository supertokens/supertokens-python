from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey as RSAPublicKey
from supertokens_python.framework.request import BaseRequest as BaseRequest
from supertokens_python.recipe.thirdparty.api.implementation import get_actual_client_id_from_development_client_id as get_actual_client_id_from_development_client_id
from supertokens_python.recipe.thirdparty.constants import APPLE_REDIRECT_HANDLER as APPLE_REDIRECT_HANDLER
from supertokens_python.recipe.thirdparty.provider import Provider as Provider
from supertokens_python.recipe.thirdparty.types import AccessTokenAPI as AccessTokenAPI, AuthorisationRedirectAPI as AuthorisationRedirectAPI, UserInfo as UserInfo, UserInfoEmail as UserInfoEmail
from supertokens_python.supertokens import Supertokens as Supertokens
from typing import Any, Callable, Dict, List, Union

class Apple(Provider):
    APPLE_PUBLIC_KEY_URL: str
    APPLE_PUBLIC_KEYS: Any
    APPLE_KEY_CACHE_EXP: Any
    apple_last_fetch: int
    client_key_id: Any
    client_private_key: Any
    client_team_id: Any
    scopes: Any
    access_token_api_url: str
    authorisation_redirect_url: str
    authorisation_redirect_params: Any
    def __init__(self, client_id: str, client_key_id: str, client_private_key: str, client_team_id: str, scope: Union[None, List[str]] = ..., authorisation_redirect: Union[None, Dict[str, Union[Callable[[BaseRequest], str], str]]] = ..., is_default: bool = ...) -> None: ...
    async def get_profile_info(self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]) -> UserInfo: ...
    def get_authorisation_redirect_api_info(self, user_context: Dict[str, Any]) -> AuthorisationRedirectAPI: ...
    def get_access_token_api_info(self, redirect_uri: str, auth_code_from_request: str, user_context: Dict[str, Any]) -> AccessTokenAPI: ...
    def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]: ...
