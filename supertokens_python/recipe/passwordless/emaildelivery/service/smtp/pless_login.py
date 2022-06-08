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

from string import Template
from typing import TYPE_CHECKING, Union

from supertokens_python.ingredients.emaildelivery.services.smtp import \
    GetContentResult
from supertokens_python.supertokens import Supertokens
from supertokens_python.utils import humanize_time

from .pless_login_email import (html_template, otp_body, table_body,
                                url_link_body)

if TYPE_CHECKING:
    from supertokens_python.recipe.passwordless.interfaces import \
        TypePasswordlessEmailDeliveryInput


def pless_email_content(input_: TypePasswordlessEmailDeliveryInput) -> GetContentResult:
    supertokens = Supertokens.get_instance()
    app_name = supertokens.app_info.app_name
    code_lifetime = humanize_time(input_.code_life_time)
    body = get_pless_email_html(app_name, code_lifetime, input_.email, input_.url_with_link_code, input_.user_input_code)
    content_result = GetContentResult(body, "Passwordless auth instructions", input_.email, True)
    return content_result


def get_pless_email_html(
    app_name: str, code_lifetime: str, email: str,
    url_with_link_code: Union[str, None] = None,
    user_input_code: Union[str, None] = None,
):
    main_body = ""
    if user_input_code is not None:
        main_body += otp_body
    if user_input_code is not None and url_with_link_code is not None:
        main_body += table_body
    if url_with_link_code is not None:
        main_body += url_link_body

    substitutes = {
        "appName": app_name,
        "codeLifetime": code_lifetime,
        "email": email,
        "urlWithLinkCode": url_with_link_code,
        "userInputCode": user_input_code,
    }

    main_body = Template(main_body).substitute(**substitutes)

    substitutes["mainBody"] = main_body
    return Template(html_template).substitute(**substitutes)
