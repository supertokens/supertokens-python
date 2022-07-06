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
from textwrap import dedent
from typing import TYPE_CHECKING, Union

from supertokens_python.ingredients.smsdelivery.types import SMSContent
from supertokens_python.supertokens import Supertokens
from supertokens_python.utils import humanize_time

if TYPE_CHECKING:
    from supertokens_python.recipe.passwordless.types import (
        PasswordlessLoginSMSTemplateVars,
    )


def pless_sms_content(input_: PasswordlessLoginSMSTemplateVars) -> SMSContent:
    supertokens = Supertokens.get_instance()
    app_name = supertokens.app_info.app_name
    code_lifetime = humanize_time(input_.code_life_time)
    body = get_pless_sms_body(
        app_name, code_lifetime, input_.url_with_link_code, input_.user_input_code
    )
    return SMSContent(body, input_.phone_number)


def get_pless_sms_body(
    app_name: str,
    code_lifetime: str,
    url_with_link_code: Union[str, None] = None,
    user_input_code: Union[str, None] = None,
) -> str:
    if (url_with_link_code is not None) and (user_input_code is not None):
        sms_template = dedent(
            """\
        OTP to login is ${otp} for ${appname}

        Or click ${magicLink} to login.

        This is valid for ${time}."""
        )
    elif url_with_link_code is not None:
        sms_template = dedent(
            """\
        Click ${magicLink} to login to ${appname}

        This is valid for ${time}."""
        )
    elif user_input_code is not None:
        sms_template = dedent(
            """\
        OTP to login is ${otp} for ${appname}

        This is valid for ${time}."""
        )
    else:
        raise Exception("This should never be thrown.")

    return Template(sms_template).substitute(
        appname=app_name,
        magicLink=url_with_link_code,
        otp=user_input_code,
        time=code_lifetime,
    )
