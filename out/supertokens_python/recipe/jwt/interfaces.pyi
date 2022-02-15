import abc
from .utils import JWTConfig as JWTConfig
from abc import ABC, abstractmethod
from supertokens_python.framework import BaseRequest as BaseRequest, BaseResponse as BaseResponse
from typing import Any, Dict, List, Union
from typing_extensions import Literal

class JsonWebKey:
    kty: Any
    kid: Any
    n: Any
    e: Any
    alg: Any
    use: Any
    def __init__(self, kty: str, kid: str, n: str, e: str, alg: str, use: str) -> None: ...

class CreateJwtResult(ABC):
    status: Any
    jwt: Any
    def __init__(self, status: Literal['OK', 'UNSUPPORTED_ALGORITHM_ERROR'], jwt: Union[None, str] = ...) -> None: ...

class CreateJwtResultOk(CreateJwtResult):
    def __init__(self, jwt: str) -> None: ...

class CreateJwtResultUnsupportedAlgorithm(CreateJwtResult):
    def __init__(self) -> None: ...

class GetJWKSResult(ABC):
    status: Any
    keys: Any
    def __init__(self, status: Literal['OK'], keys: List[JsonWebKey]) -> None: ...

class RecipeInterface(ABC, metaclass=abc.ABCMeta):
    def __init__(self) -> None: ...
    @abstractmethod
    async def create_jwt(self, payload: Dict[str, Any], validity_seconds: Union[int, None], user_context: Dict[str, Any]) -> CreateJwtResult: ...
    @abstractmethod
    async def get_jwks(self, user_context: Dict[str, Any]) -> GetJWKSResult: ...

class APIOptions:
    request: Any
    response: Any
    recipe_id: Any
    config: Any
    recipe_implementation: Any
    def __init__(self, request: BaseRequest, response: BaseResponse, recipe_id: str, config: JWTConfig, recipe_implementation: RecipeInterface) -> None: ...

class JWKSGetResponse:
    status: Any
    keys: Any
    def __init__(self, status: Literal['OK'], keys: List[JsonWebKey]) -> None: ...
    def to_json(self) -> Dict[str, Any]: ...

class APIInterface(metaclass=abc.ABCMeta):
    disable_jwks_get: bool
    def __init__(self) -> None: ...
    @abstractmethod
    async def jwks_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> JWKSGetResponse: ...
