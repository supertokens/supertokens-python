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

from typing import Any, Callable, Dict, Union

from supertokens_python.ingredients.emaildelivery.services.smtp import Transporter
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryInterface,
    SMTPServiceInterface,
    SMTPSettings,
)
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnEmailDeliveryInput,
)

from .service_implementation.base import ServiceImplementation


class SMTPService(EmailDeliveryInterface[TypeWebauthnEmailDeliveryInput]):
    service_implementation: SMTPServiceInterface[TypeWebauthnEmailDeliveryInput]

    def __init__(
        self,
        smtp_settings: SMTPSettings,
        override: Union[
            Callable[
                [SMTPServiceInterface[TypeWebauthnEmailDeliveryInput]],
                SMTPServiceInterface[TypeWebauthnEmailDeliveryInput],
            ],
            None,
        ] = None,
    ) -> None:
        transporter = Transporter(smtp_settings)

        oi = ServiceImplementation(transporter)
        self.service_implementation = oi if override is None else override(oi)

    async def send_email(
        self,
        template_vars: TypeWebauthnEmailDeliveryInput,
        user_context: Dict[str, Any],
    ) -> None:
        content = await self.service_implementation.get_content(
            template_vars, user_context
        )
        await self.service_implementation.send_raw_email(content, user_context)
