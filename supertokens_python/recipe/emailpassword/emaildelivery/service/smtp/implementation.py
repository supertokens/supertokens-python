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
from supertokens_python.recipe.emailpassword.emaildelivery.service.smtp.password_reset_implementation import \
    getPasswordResetEmailContent
from supertokens_python.recipe.emailpassword.types import \
    TypeEmailPasswordEmailDeliveryInput
from supertokens_python.recipe.emailverification.emaildelivery.service.smtp import \
    getServiceImplementation as \
    getEmailVerificationEmailDeliveryServiceImplementation
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput


class DefaultServiceImplementation(ServiceInterface[TypeEmailPasswordEmailDeliveryInput]):
    def __init__(self, transporter: Transporter, emailVerificationSeriveImpl: ServiceInterface[TypeEmailVerificationEmailDeliveryInput]) -> None:
        self.transporter = transporter
        self.emailVerificationSeriveImpl = emailVerificationSeriveImpl

    async def send_raw_email(self, get_content_result: GetContentResult, config_from: SMTPServiceConfigFrom, user_context: Dict[str, Any]) -> None:
        self.transporter.send_email(config_from, get_content_result, user_context)

    def get_content(self, email_input: TypeEmailPasswordEmailDeliveryInput, user_context: Dict[str, Any]) -> GetContentResult:
        if isinstance(email_input, TypeEmailVerificationEmailDeliveryInput):
            return self.emailVerificationSeriveImpl.get_content(email_input, user_context)  # FIXME: Node SDK has DerivedEV
        return getPasswordResetEmailContent(email_input)


def getServiceImplementation(transporter: Transporter, input_send_raw_email_from: SMTPServiceConfigFrom) -> ServiceInterface[TypeEmailPasswordEmailDeliveryInput]:
    emailVerificationSeriveImpl = getEmailVerificationEmailDeliveryServiceImplementation(transporter, input_send_raw_email_from)
    si = DefaultServiceImplementation(transporter, emailVerificationSeriveImpl)
    return si
