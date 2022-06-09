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

from supertokens_python.ingredients.emaildelivery.services.smtp import (
    GetContentResult, ServiceInterface, Transporter)
from supertokens_python.recipe.emailverification.emaildelivery.services.smtp.service_implementation import \
    ServiceImplementation as EVServiceImplementation
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.passwordless.emaildelivery.services.smtp.service_implementation import \
    ServiceImplementation as PlessServiceImplementation
from supertokens_python.recipe.thirdpartypasswordless.types import \
    TypeThirdPartyPasswordlessEmailDeliveryInput

from .email_verification_implementation import \
    ServiceImplementation as DerivedEVServiceImplementation
from .passwordless_implementation import \
    ServiceImplementation as DerivedPlessServiceImplementation


class ServiceImplementation(ServiceInterface[TypeThirdPartyPasswordlessEmailDeliveryInput]):
    def __init__(self, transporter: Transporter) -> None:
        super().__init__(transporter)

        # Email Verification:
        email_verification_service_impl = EVServiceImplementation(transporter)
        self.ev_send_raw_email = email_verification_service_impl.send_raw_email
        self.ev_get_content = email_verification_service_impl.get_content

        derived_ev_service_implementation = DerivedEVServiceImplementation(self)
        email_verification_service_impl.send_raw_email = derived_ev_service_implementation.send_raw_email
        email_verification_service_impl.get_content = derived_ev_service_implementation.get_content

        # Passwordless:
        pless_service_impl = PlessServiceImplementation(transporter)
        self.pless_send_raw_email = pless_service_impl.send_raw_email
        self.pless_get_content = pless_service_impl.get_content

        derived_pless_service_implementation = DerivedPlessServiceImplementation(self)
        pless_service_impl.send_raw_email = derived_pless_service_implementation.send_raw_email
        pless_service_impl.get_content = derived_pless_service_implementation.get_content

    async def send_raw_email(self, input_: GetContentResult, user_context: Dict[str, Any]) -> None:
        await self.transporter.send_email(input_, user_context)

    async def get_content(self, input_: TypeThirdPartyPasswordlessEmailDeliveryInput, user_context: Dict[str, Any]) -> GetContentResult:
        if isinstance(input_, TypeEmailVerificationEmailDeliveryInput):
            return await self.ev_get_content(input_, user_context)

        return await self.pless_get_content(input_, user_context)
