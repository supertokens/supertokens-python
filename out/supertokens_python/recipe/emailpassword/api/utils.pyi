from supertokens_python.exceptions import raise_bad_input_exception as raise_bad_input_exception
from supertokens_python.recipe.emailpassword.constants import FORM_FIELD_EMAIL_ID as FORM_FIELD_EMAIL_ID
from supertokens_python.recipe.emailpassword.exceptions import raise_form_field_exception as raise_form_field_exception
from supertokens_python.recipe.emailpassword.types import ErrorFormField as ErrorFormField, FormField as FormField, NormalisedFormField as NormalisedFormField
from supertokens_python.utils import find_first_occurrence_in_list as find_first_occurrence_in_list
from typing import Any, List

async def validate_form_or_throw_error(inputs: List[FormField], config_form_fields: List[NormalisedFormField]): ...
async def validate_form_fields_or_throw_error(config_form_fields: List[NormalisedFormField], form_fields_raw: Any) -> List[FormField]: ...
