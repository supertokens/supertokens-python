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

from twilio.rest import Client  # type: ignore

_T = TypeVar('_T')


class TwilioServiceConfig:
    def __init__(self,
                 account_sid: str,
                 auth_token: str,
                 from_: Union[str, None] = None,
                 messaging_service_sid: Union[str, None] = None,
                 opts: Union[Dict[str, Any], None] = None,
                 ) -> None:
        """
        Note: `self.otps` can be used to override values passed to the Twilio Client.
        Read docs from `twilio.rest.Client.__init__` to discover possible args.

        For example, `opts = {"region": "...", "user_agent_extensions": ["..."], }`
        """
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_ = from_
        self.messaging_service_sid = messaging_service_sid
        self.opts = opts


class GetContentResult:
    def __init__(self, body: str, to_phone: str) -> None:
        self.body = body
        self.to_phone = to_phone


class ServiceInterface(ABC, Generic[_T]):
    def __init__(self, twilio_client: Client) -> None:  # type: ignore
        self.twilio_client = twilio_client  # type: ignore

    @abstractmethod
    async def send_raw_sms(self,
                           get_content_result: GetContentResult,
                           user_context: Dict[str, Any],
                           from_: Union[str, None] = None,
                           messaging_service_sid: Union[str, None] = None,
                           ) -> None:
        pass

    @abstractmethod
    async def get_content(self, input_: _T, user_context: Dict[str, Any]) -> GetContentResult:
        pass


class SMSDeliveryTwilioConfig(Generic[_T]):
    def __init__(self,
                 twilio_settings: TwilioServiceConfig,
                 override: Union[Callable[[ServiceInterface[_T]], ServiceInterface[_T]], None] = None
                 ) -> None:
        self.twilio_settings = twilio_settings
        self.override = override


def normalize_twilio_config(sms_input: SMSDeliveryTwilioConfig[_T]) -> SMSDeliveryTwilioConfig[_T]:
    from_ = sms_input.twilio_settings.from_
    messaging_service_sid = sms_input.twilio_settings.messaging_service_sid

    if (from_ and messaging_service_sid) or (not from_ and not messaging_service_sid):
        raise Exception('Please pass exactly one of "from" and "messaging_service_sid" config for twilio_settings.')

    return sms_input
