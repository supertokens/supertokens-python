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

from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery.service.smtp import (
    GetContentResult, ServiceInterface, SMTPServiceConfigFrom, Transporter)
from supertokens_python.recipe.emailverification.emaildelivery.service.smtp.email_verify import \
    get_email_verify_email_content
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput


class ServiceImplementation(ServiceInterface[TypeEmailVerificationEmailDeliveryInput]):
    def __init__(self, transporter: Transporter) -> None:
        self.transporter = transporter

    async def send_raw_email(self, get_content_result: GetContentResult, config_from: SMTPServiceConfigFrom, user_context: Dict[str, Any]) -> None:
        self.transporter.send_email(config_from, get_content_result, user_context)

    async def get_content(self, email_input: TypeEmailVerificationEmailDeliveryInput, user_context: Dict[str, Any]) -> GetContentResult:
        return get_email_verify_email_content(email_input)
