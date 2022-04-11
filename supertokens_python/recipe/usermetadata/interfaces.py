from abc import ABC, abstractmethod
from typing import Any, Dict


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_metadata(self, user_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def update_user_metadata(self, user_id: str, metadata_update: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def clear_user_metadata(self, user_id: str) -> Dict[str, Any]:
        pass


class APIInterface:
    pass
