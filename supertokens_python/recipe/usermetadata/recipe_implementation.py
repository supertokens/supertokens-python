

from typing import Any, Dict

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

from .interfaces import RecipeInterface


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def get_user_metadata(self, user_id: str) -> Dict[str, Any]:
        params = {"userId": user_id}
        return await self.querier.send_get_request(NormalisedURLPath("/recipe/user/metadata"), params)

    async def update_user_metadata(self, user_id: str, metadata_update: Dict[str, Any]) -> Dict[str, Any]:
        params = {"userId": user_id, "metadataUpdate": metadata_update}
        return await self.querier.send_put_request(NormalisedURLPath("/recipe/user/metadata"), params)

    async def clear_user_metadata(self, user_id: str) -> Dict[str, Any]:
        params = {"userId": user_id}
        return await self.querier.send_post_request(NormalisedURLPath("/recipe/user/metadata/remove"), params)
