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

from typing import Any, Dict, Union

from supertokens_python.ingredients.smsdelivery.types import (
    SMSContent,
    TwilioServiceInterface,
)
from supertokens_python.recipe.passwordless.smsdelivery.services.twilio.passwordless_login import (
    pless_sms_content,
)
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginSMSTemplateVars,
)


class ServiceImplementation(TwilioServiceInterface[PasswordlessLoginSMSTemplateVars]):
    async def send_raw_sms(
        self,
        content: SMSContent,
        user_context: Dict[str, Any],
        from_: Union[str, None] = None,
        messaging_service_sid: Union[str, None] = None,
    ) -> None:
        if from_:
            self.twilio_client.messages.create(  # type: ignore
                to=content.to_phone,
                body=content.body,
                from_=from_,
            )
        else:
            self.twilio_client.messages.create(  # type: ignore
                to=content.to_phone,
                body=content.body,
                messaging_service_sid=messaging_service_sid,
            )

    async def get_content(
        self,
        template_vars: PasswordlessLoginSMSTemplateVars,
        user_context: Dict[str, Any],
    ) -> SMSContent:
        _ = user_context
        return pless_sms_content(template_vars)
