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

from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery.service.smtp import (
    GetContentResult, ServiceInterface, SMTPServiceConfigFrom, Transporter)
from supertokens_python.recipe.passwordless.emaildelivery.service.smtp.pless_email import \
    pless_email_content
from supertokens_python.recipe.passwordless.utils import \
    CreateAndSendCustomEmailParameters as TypePasswordlessEmailDeliveryInput


class ServiceImplementation(ServiceInterface[TypePasswordlessEmailDeliveryInput]):
    def __init__(self, transporter: Transporter) -> None:
        self.transporter = transporter

    async def send_raw_email(self, get_content_result: GetContentResult, config_from: SMTPServiceConfigFrom, user_context: Dict[str, Any]) -> None:
        await self.transporter.send_email(config_from, get_content_result, user_context)

    async def get_content(self, email_input: TypePasswordlessEmailDeliveryInput, user_context: Dict[str, Any]) -> GetContentResult:
        return pless_email_content(email_input)
