# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from __future__ import annotations

from typing import Any, Dict, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailpassword.constants import FORM_FIELD_EMAIL_ID
from supertokens_python.recipe.emailpassword.exceptions import (
    raise_form_field_exception,
)
from supertokens_python.recipe.emailpassword.types import (
    ErrorFormField,
    FormField,
    NormalisedFormField,
)
from supertokens_python.utils import find_first_occurrence_in_list


async def validate_form_or_throw_error(
    inputs: List[FormField], config_form_fields: List[NormalisedFormField]
):
    validation_errors: List[ErrorFormField] = []
    if len(config_form_fields) != len(inputs):
        raise_bad_input_exception("Are you sending too many / too few formFields?")

    for field in config_form_fields:
        input_field: Union[None, FormField] = find_first_occurrence_in_list(
            lambda x: x.id == field.id, inputs
        )
        if input_field is None or (input_field.value == "" and not field.optional):
            validation_errors.append(ErrorFormField(field.id, "Field is not optional"))
        else:
            error = await field.validate(input_field.value)
            if error is not None:
                validation_errors.append(ErrorFormField(field.id, error))

    if len(validation_errors) != 0:
        # raise BadInputError(msg="Error in input formFields")
        raise_form_field_exception("Error in input formFields", validation_errors)


async def validate_form_fields_or_throw_error(
    config_form_fields: List[NormalisedFormField], form_fields_raw: Any
) -> List[FormField]:
    if form_fields_raw is None:
        raise_bad_input_exception("Missing input param: formFields")

    if not isinstance(form_fields_raw, List):
        raise_bad_input_exception("formFields must be an array")

    form_fields: List[FormField] = []

    form_fields_list_raw: List[Dict[str, Any]] = form_fields_raw
    for current_form_field in form_fields_list_raw:
        if (
            "id" not in current_form_field
            or not isinstance(current_form_field["id"], str)
            or "value" not in current_form_field
        ):
            raise_bad_input_exception(
                "All elements of formFields must contain an 'id' and 'value' field"
            )
        value = current_form_field["value"]
        if current_form_field["id"] == FORM_FIELD_EMAIL_ID and isinstance(value, str):
            value = value.strip()
        form_fields.append(FormField(current_form_field["id"], value))

    await validate_form_or_throw_error(form_fields, config_form_fields)
    return form_fields
