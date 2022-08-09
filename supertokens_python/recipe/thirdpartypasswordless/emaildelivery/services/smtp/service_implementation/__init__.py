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

from supertokens_python.ingredients.emaildelivery.services.smtp import Transporter
from supertokens_python.ingredients.emaildelivery.types import (
    EmailContent,
    SMTPServiceInterface,
)
from supertokens_python.recipe.passwordless.emaildelivery.services.smtp.service_implementation import (
    ServiceImplementation as PlessServiceImplementation,
)
from supertokens_python.recipe.thirdpartypasswordless.types import EmailTemplateVars

from .passwordless_implementation import (
    ServiceImplementation as DerivedPlessServiceImplementation,
)


class ServiceImplementation(SMTPServiceInterface[EmailTemplateVars]):
    def __init__(self, transporter: Transporter) -> None:
        super().__init__(transporter)

        # Passwordless:
        pless_service_impl = PlessServiceImplementation(transporter)
        self.pless_send_raw_email = pless_service_impl.send_raw_email
        self.pless_get_content = pless_service_impl.get_content

        derived_pless_service_implementation = DerivedPlessServiceImplementation(self)
        pless_service_impl.send_raw_email = (
            derived_pless_service_implementation.send_raw_email
        )
        pless_service_impl.get_content = (
            derived_pless_service_implementation.get_content
        )

    async def send_raw_email(
        self, content: EmailContent, user_context: Dict[str, Any]
    ) -> None:
        await self.transporter.send_email(content, user_context)

    async def get_content(
        self, template_vars: EmailTemplateVars, user_context: Dict[str, Any]
    ) -> EmailContent:
        return await self.pless_get_content(template_vars, user_context)
