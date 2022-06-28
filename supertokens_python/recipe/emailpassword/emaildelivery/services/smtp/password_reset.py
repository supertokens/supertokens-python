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

from string import Template

from supertokens_python.ingredients.emaildelivery.types import EmailContent
from supertokens_python.recipe.emailpassword.types import PasswordResetEmailTemplateVars
from supertokens_python.supertokens import Supertokens

from .password_reset_email import html_template


def get_password_reset_email_content(
    email_input: PasswordResetEmailTemplateVars,
) -> EmailContent:
    supertokens = Supertokens.get_instance()
    app_name = supertokens.app_info.app_name
    body = get_password_reset_email_html(
        app_name, email_input.user.email, email_input.password_reset_link
    )
    content_result = EmailContent(
        body, "Password reset instructions", email_input.user.email, is_html=True
    )
    return content_result


def get_password_reset_email_html(app_name: str, email: str, reset_link: str):
    return Template(html_template).substitute(
        appname=app_name, resetLink=reset_link, toEmail=email
    )
