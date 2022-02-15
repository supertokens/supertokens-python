from supertokens_python.exceptions import raise_bad_input_exception as raise_bad_input_exception
from supertokens_python.recipe.passwordless.interfaces import APIInterface as APIInterface, APIOptions as APIOptions

async def email_exists(api_implementation: APIInterface, api_options: APIOptions): ...
