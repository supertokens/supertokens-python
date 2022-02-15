from supertokens_python.exceptions import raise_bad_input_exception as raise_bad_input_exception
from supertokens_python.recipe.thirdparty.interfaces import APIInterface as APIInterface, APIOptions as APIOptions
from supertokens_python.recipe.thirdparty.provider import Provider as Provider
from supertokens_python.recipe.thirdparty.utils import find_right_provider as find_right_provider

async def handle_authorisation_url_api(api_implementation: APIInterface, api_options: APIOptions): ...
