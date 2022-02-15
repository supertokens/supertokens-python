from supertokens_python.exceptions import raise_general_exception as raise_general_exception
from supertokens_python.recipe.session.asyncio import create_new_session as create_new_session
from supertokens_python.recipe.thirdparty.interfaces import APIInterface as APIInterface, APIOptions as APIOptions, AuthorisationUrlGetOkResponse as AuthorisationUrlGetOkResponse, AuthorisationUrlGetResponse as AuthorisationUrlGetResponse, SignInUpPostFieldErrorResponse as SignInUpPostFieldErrorResponse, SignInUpPostNoEmailGivenByProviderResponse as SignInUpPostNoEmailGivenByProviderResponse, SignInUpPostOkResponse as SignInUpPostOkResponse, SignInUpPostResponse as SignInUpPostResponse
from supertokens_python.recipe.thirdparty.provider import Provider as Provider
from supertokens_python.recipe.thirdparty.types import UserInfo as UserInfo
from typing import Any, Dict, Union

DEV_OAUTH_CLIENT_IDS: Any
DEV_KEY_IDENTIFIER: str
DEV_OAUTH_AUTHORIZATION_URL: str
DEV_OAUTH_REDIRECT_URL: str

def is_using_oauth_development_client_id(client_id: str): ...
def get_actual_client_id_from_development_client_id(client_id: str): ...

class APIImplementation(APIInterface):
    async def authorisation_url_get(self, provider: Provider, api_options: APIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse: ...
    async def sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None], api_options: APIOptions, user_context: Dict[str, Any]) -> SignInUpPostResponse: ...
    async def apple_redirect_handler_post(self, code: str, state: str, api_options: APIOptions, user_context: Dict[str, Any]): ...
