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

from supertokens_python.ingredients.smsdelivery.service.twilio import (
    GetContentResult, ServiceInterface)
from supertokens_python.recipe.passwordless.smsdelivery.service.twilio.pless_sms import \
    pless_sms_content
from supertokens_python.recipe.passwordless.types import \
    TypePasswordlessSmsDeliveryInput

from twilio.rest import Client  # type: ignore


class ServiceImplementation(ServiceInterface[TypePasswordlessSmsDeliveryInput]):
    def __init__(self,
                 twilio_client: Client  # type: ignore
                 ) -> None:
        self.twilio_client = twilio_client  # type: ignore

    async def send_raw_sms(self,
                           get_content_result: GetContentResult,
                           user_context: Dict[str, Any],
                           from_: Union[str, None] = None,
                           sid: Union[str, None] = None,
                           ) -> None:
        if from_:
            self.twilio_client.messages.create(  # type: ignore
                to=get_content_result.to_phone,
                body=get_content_result.body,
                from_=from_,
            )
        else:
            self.twilio_client.messages.create(  # type: ignore
                to=get_content_result.to_phone,
                body=get_content_result.body,
                messaging_service_sid=sid,
            )

    async def get_content(self, input_: TypePasswordlessSmsDeliveryInput) -> GetContentResult:
        return pless_sms_content(input_)
