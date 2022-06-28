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

from typing import TYPE_CHECKING, Any, Dict, List

from supertokens_python.exceptions import SuperTokensError

if TYPE_CHECKING:
    from .types import ErrorFormField


def raise_form_field_exception(msg: str, form_fields: List[ErrorFormField]):
    raise FieldError(msg, form_fields)


class SuperTokensEmailPasswordError(SuperTokensError):
    pass


class FieldError(SuperTokensEmailPasswordError):
    def __init__(self, msg: str, form_fields: List[ErrorFormField]):
        super().__init__(msg)
        self.form_fields = form_fields

    def get_json_form_fields(self) -> List[Dict[str, Any]]:
        form_fields: List[Dict[str, Any]] = []
        for form_field in self.form_fields:
            form_fields.append({"id": form_field.id, "error": form_field.error})
        return form_fields
