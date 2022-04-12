from abc import ABC, abstractmethod
from typing import Any, Dict, Literal


class GetUserMetadataResult(ABC):
    def __init__(self, status: Literal['OK'], metadata: Dict[str, Any]):
        self.status = status
        self.is_ok = status == 'OK'
        self.metadata = metadata


class UpdateUserMetadataResult(ABC):
    def __init__(self, status: Literal['OK'], metadata: Dict[str, Any]):
        self.status = status
        self.is_ok = status == 'OK'
        self.metadata = metadata


class ClearUserMetadataResult(ABC):
    def __init__(self, status: Literal['OK']):
        self.status = status
        self.is_ok = status == 'OK'


class RecipeInterface(ABC):
    @abstractmethod
    async def get_user_metadata(self, user_id: str, user_context: Dict[str, Any]) -> GetUserMetadataResult:
        pass

    @abstractmethod
    async def update_user_metadata(self, user_id: str, metadata_update: Dict[str, Any], user_context: Dict[str, Any]) -> UpdateUserMetadataResult:
        pass

    @abstractmethod
    async def clear_user_metadata(self, user_id: str, user_context: Dict[str, Any]) -> ClearUserMetadataResult:
        pass


class APIInterface(ABC):
    pass
