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

from os import path
from string import Template

from supertokens_python.ingredients.emaildelivery.services.smtp import \
    GetContentResult
from supertokens_python.recipe.passwordless.interfaces import \
    TypePasswordlessEmailDeliveryInput
from supertokens_python.supertokens import Supertokens


def pless_email_content(email_input: TypePasswordlessEmailDeliveryInput) -> GetContentResult:
    # TODO: FIXME (func name, email title, etc)
    supertokens = Supertokens.get_instance()
    app_name = supertokens.app_info.app_name
    body = get_pless_email_html(app_name, email_input.email, str(email_input.code_life_time))
    content_result = GetContentResult(body, "Passwordless auth instructions", email_input.email, True)
    return content_result


def get_pless_email_html(appName: str, email: str, verificationLink: str):
    # TODO: FIXME (func name, email title, etc)
    current_dir = path.dirname(__file__)
    template_path = path.join(current_dir, "pless_email.html")
    template = open(template_path, "r").read()

    return Template(template).substitute(appName=appName, verificationLink=verificationLink, email=email)
