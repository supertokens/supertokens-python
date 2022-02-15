from .utils import validate_form_fields_or_throw_error as validate_form_fields_or_throw_error
from supertokens_python.exceptions import raise_bad_input_exception as raise_bad_input_exception
from supertokens_python.recipe.emailpassword.interfaces import APIInterface as APIInterface, APIOptions as APIOptions

async def handle_password_reset_api(api_implementation: APIInterface, api_options: APIOptions): ...
