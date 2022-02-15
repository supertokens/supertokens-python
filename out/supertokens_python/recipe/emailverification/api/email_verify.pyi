from supertokens_python.exceptions import raise_bad_input_exception as raise_bad_input_exception
from supertokens_python.recipe.emailverification.interfaces import APIInterface as APIInterface, APIOptions as APIOptions
from supertokens_python.utils import normalise_http_method as normalise_http_method

async def handle_email_verify_api(api_implementation: APIInterface, api_options: APIOptions): ...
