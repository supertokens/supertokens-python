from ..interfaces import SessionContainer as SessionContainer
from supertokens_python.normalised_url_path import NormalisedURLPath as NormalisedURLPath
from supertokens_python.recipe.session.exceptions import UnauthorisedError as UnauthorisedError
from supertokens_python.recipe.session.interfaces import APIInterface as APIInterface, APIOptions as APIOptions, SignOutOkayResponse as SignOutOkayResponse, SignOutResponse as SignOutResponse
from supertokens_python.utils import normalise_http_method as normalise_http_method
from typing import Any, Dict, Union

class APIImplementation(APIInterface):
    async def refresh_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> None: ...
    async def signout_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> SignOutResponse: ...
    async def verify_session(self, api_options: APIOptions, anti_csrf_check: Union[bool, None], session_required: bool, user_context: Dict[str, Any]) -> Union[SessionContainer, None]: ...
