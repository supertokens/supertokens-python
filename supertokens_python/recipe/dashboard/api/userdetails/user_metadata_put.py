import json
from typing import Any, Dict

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.usermetadata.asyncio import (
    clear_user_metadata,
    update_user_metadata,
)
from supertokens_python.types import APIResponse

from ...interfaces import APIInterface, APIOptions, APIResponse


class UserMetadataPutAPIResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


async def handle_metadata_put(
    _api_interface: APIInterface, api_options: APIOptions
) -> APIResponse:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    user_id = request_body.get("userId")
    data = request_body.get("data")

    # This is to throw an error early in case the recipe has not been initialised
    UserMetadataRecipe.get_instance()

    if user_id is None or isinstance(user_id, str) is False:
        raise_bad_input_exception(
            "Required parameter 'userId' is missing or has an invalid type"
        )

    if data is None or isinstance(data, str) is False:
        raise_bad_input_exception(
            "Required parameter 'data' is missing or has an invalid type"
        )

    try:
        parsed_data = json.loads(data)

        if not isinstance(parsed_data, dict) or parsed_data is None:
            raise Exception()

    except Exception:
        raise_bad_input_exception("'data' must be a valid JSON body")

    #
    # This API is meant to set the user metadata of a user. We delete the existing data
    # before updating it because we want to make sure that shallow merging does not result
    # in the data being incorrect
    #
    # For example if the old data is {test: "test", test2: "test2"} and the user wants to delete
    # test2 from the data simply calling updateUserMetadata with {test: "test"} would not remove
    # test2 because of shallow merging.
    #
    # Removing first ensures that the final data is exactly what the user wanted it to be

    # FIXME: This Shouldn't be required
    parsed_data_: Dict[str, Any] = parsed_data  # type: ignore

    await clear_user_metadata(user_id)
    await update_user_metadata(user_id, parsed_data_)

    return UserMetadataPutAPIResponse()
