import abc
from .utils import OpenIdConfig as OpenIdConfig
from abc import ABC, abstractmethod
from supertokens_python.framework import BaseRequest as BaseRequest, BaseResponse as BaseResponse
from supertokens_python.recipe.jwt.interfaces import CreateJwtResult as CreateJwtResult, GetJWKSResult as GetJWKSResult
from typing import Any, Dict, Union
from typing_extensions import Literal

class GetOpenIdDiscoveryConfigurationResult(ABC):
    status: Any
    issuer: Any
    jwks_uri: Any
    def __init__(self, status: Literal['OK'], issuer: str, jwks_uri: str) -> None: ...

class RecipeInterface(ABC, metaclass=abc.ABCMeta):
    def __init__(self) -> None: ...
    @abstractmethod
    async def create_jwt(self, payload: Dict[str, Any], validity_seconds: Union[int, None], user_context: Dict[str, Any]) -> CreateJwtResult: ...
    @abstractmethod
    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult: ...
    @abstractmethod
    async def get_open_id_discovery_configuration(self, user_context: Dict[str, Any]) -> GetOpenIdDiscoveryConfigurationResult: ...

class APIOptions:
    request: Any
    response: Any
    recipe_id: Any
    config: Any
    recipe_implementation: Any
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str, config: OpenIdConfig, recipe_implementation: RecipeInterface) -> None: ...

class OpenIdDiscoveryConfigurationGetResponse:
    status: Any
    issuer: Any
    jwks_uri: Any
    def __init__(self, status: Literal['OK'], issuer: str, jwks_uri: str) -> None: ...
    def to_json(self): ...

class APIInterface(metaclass=abc.ABCMeta):
    disable_open_id_discovery_configuration_get: bool
    def __init__(self) -> None: ...
    @abstractmethod
    async def open_id_discovery_configuration_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> OpenIdDiscoveryConfigurationGetResponse: ...
