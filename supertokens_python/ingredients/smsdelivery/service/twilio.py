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
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Generic, TypeVar, Union

_T = TypeVar('_T')


class TwilioServiceConfig:
    def __init__(self,
                 account_sid: str,
                 auth_token: str,
                 input_from: str,
                 sid: Union[str, None] = None,
                 opts: Union[Dict[str, Any], None] = None,
                 ) -> None:
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.input_from = input_from
        self.sid = sid
        self.opts = opts


class GetContentResult:
    def __init__(self, body: str, to_phone: str) -> None:
        self.body = body
        self.to_phone = to_phone


class ServiceInterface(ABC, Generic[_T]):
    # TODO: Might have to define __init__ later on

    @abstractmethod
    async def send_raw_sms(self,
                           get_content_result: GetContentResult,
                           user_context: Dict[str, Any],
                           input_from: Union[str, None] = None,
                           sid: Union[str, None] = None,
                           ) -> None:
        pass

    @abstractmethod
    async def get_content(self, sms_input: _T) -> GetContentResult:
        pass


class SMSDeliveryTwilioConfig(Generic[_T]):
    def __init__(self,
                 twilio_config: TwilioServiceConfig,
                 override: Union[Callable[[ServiceInterface[_T]], ServiceInterface[_T]], None] = None
                 ) -> None:
        self.twilio_config = twilio_config
        self.override = override


def normalize_twilio_config(sms_input: SMSDeliveryTwilioConfig[_T]) -> SMSDeliveryTwilioConfig[_T]:
    input_from = sms_input.twilio_config.input_from if sms_input.twilio_config.input_from is not None else None
    sid = sms_input.twilio_config.sid if sms_input.twilio_config.sid is not None else None

    if (input_from and sid) or (not input_from and not sid):
        raise Exception('Please pass exactly one of "from" and "messagingServiceSid" config for twilioSettings.')

    return sms_input
