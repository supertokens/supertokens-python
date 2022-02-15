import abc
from .types import AccessTokenAPI as AccessTokenAPI, AuthorisationRedirectAPI as AuthorisationRedirectAPI, UserInfo as UserInfo
from typing import Any, Dict, Union

class Provider(abc.ABC, metaclass=abc.ABCMeta):
    id: Any
    client_id: Any
    is_default: Any
    def __init__(self, provider_id: str, client_id: str, is_default: bool) -> None: ...
    @abc.abstractmethod
    async def get_profile_info(self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]) -> UserInfo: ...
    @abc.abstractmethod
    def get_authorisation_redirect_api_info(self, user_context: Dict[str, Any]) -> AuthorisationRedirectAPI: ...
    @abc.abstractmethod
    def get_access_token_api_info(self, redirect_uri: str, auth_code_from_request: str, user_context: Dict[str, Any]) -> AccessTokenAPI: ...
    @abc.abstractmethod
    def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]: ...
