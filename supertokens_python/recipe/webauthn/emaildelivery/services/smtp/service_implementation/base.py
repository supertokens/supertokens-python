# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

from supertokens_python.ingredients.emaildelivery.types import (
    EmailContent,
    SMTPServiceInterface,
)
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnEmailDeliveryInput,
)

from ..recover_account import (
    get_recover_account_email_content,
)


class ServiceImplementation(SMTPServiceInterface[TypeWebauthnEmailDeliveryInput]):
    async def send_raw_email(
        self, content: EmailContent, user_context: Dict[str, Any]
    ) -> None:
        await self.transporter.send_email(content, user_context)

    async def get_content(
        self,
        template_vars: TypeWebauthnEmailDeliveryInput,
        user_context: Dict[str, Any],
    ) -> EmailContent:
        return get_recover_account_email_content(template_vars)
