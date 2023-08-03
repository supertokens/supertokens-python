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

from typing import Any, Dict, Callable, Union

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryInterface,
    SMTPSettings,
)
from supertokens_python.recipe.emailpassword.emaildelivery.services.smtp import (
    SMTPService as EmailPasswordSMTPService,
)
from supertokens_python.recipe.thirdpartyemailpassword.types import (
    EmailTemplateVars,
    SMTPOverrideInput,
)


class SMTPService(EmailDeliveryInterface[EmailTemplateVars]):
    ep_smtp_service: EmailPasswordSMTPService

    def __init__(
        self,
        smtp_settings: SMTPSettings,
        override: Union[Callable[[SMTPOverrideInput], SMTPOverrideInput], None] = None,
    ) -> None:
        self.ep_smtp_service = EmailPasswordSMTPService(smtp_settings, override)

    async def send_email(
        self,
        template_vars: EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        await self.ep_smtp_service.send_email(template_vars, user_context)
