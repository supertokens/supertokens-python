from abc import ABC, abstractmethod
from typing import Any, Dict


class MetadataResult(ABC):
    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata


class ClearUserMetadataResult:
    pass


class RecipeInterface(ABC):
    @abstractmethod
    async def get_user_metadata(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> MetadataResult:
        pass

    @abstractmethod
    async def update_user_metadata(
        self,
        user_id: str,
        metadata_update: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> MetadataResult:
        pass

    @abstractmethod
    async def clear_user_metadata(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> ClearUserMetadataResult:
        pass


class APIInterface(ABC):
    pass
