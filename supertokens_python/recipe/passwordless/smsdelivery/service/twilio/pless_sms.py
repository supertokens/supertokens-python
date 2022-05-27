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

from supertokens_python.ingredients.smsdelivery.service.twilio import \
    GetContentResult

if TYPE_CHECKING:
    from supertokens_python.recipe.passwordless.types import \
        TypePasswordlessSmsDeliveryInput


def pless_sms_content(sms_input: TypePasswordlessSmsDeliveryInput) -> GetContentResult:
    body = get_pless_sms_body(sms_input.code_life_time, sms_input.url_with_link_code, sms_input.user_input_code)
    return GetContentResult(body, sms_input.phone_number)


def get_pless_sms_body(
    code_lifetime: int,
    url_with_link_code: Union[str, None] = None,
    user_input_code: Union[str, None] = None
):

    if url_with_link_code and user_input_code:
        template = "Enter OTP: ${userInputCode} OR click this link: ${urlWithLinkCode} to login."
    elif url_with_link_code:
        template = "Click this link: ${urlWithLinkCode} to login."
    else:
        template = "Enter OTP: ${userInputCode} to login."

    template += " It will expire in ${codeLifetime} seconds."

    return Template(template).substitute(
        codeLifetime=code_lifetime,
        urlWithLinkCode=url_with_link_code,
        userInputCode=user_input_code
    )
