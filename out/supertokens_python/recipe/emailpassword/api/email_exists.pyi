from supertokens_python.exceptions import raise_bad_input_exception as raise_bad_input_exception
from supertokens_python.recipe.emailpassword.interfaces import APIInterface as APIInterface, APIOptions as APIOptions

async def handle_email_exists_api(api_implementation: APIInterface, api_options: APIOptions): ...
