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
from typing import List, Union

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import (
    SMTPServiceInterface,
    EmailDeliveryInterface,
)
from supertokens_python.ingredients.smsdelivery import SMSDeliveryIngredient
from supertokens_python.ingredients.smsdelivery.types import (
    TwilioServiceInterface,
    SMSDeliveryInterface,
)


class User:
    def __init__(
        self,
        user_id: str,
        email: Union[str, None],
        phone_number: Union[str, None],
        time_joined: int,
    ):
        self.user_id: str = user_id
        self.email: Union[str, None] = email
        self.phone_number: Union[str, None] = phone_number
        self.time_joined: int = time_joined


class DeviceCode:
    def __init__(self, code_id: str, time_created: str, code_life_time: int):
        self.code_id = code_id
        self.time_created = time_created
        self.code_life_time = code_life_time


class DeviceType:
    def __init__(
        self,
        pre_auth_session_id: str,
        failed_code_input_attempt_count: int,
        codes: List[DeviceCode],
        email: Union[str, None] = None,
        phone_number: Union[str, None] = None,
    ):
        self.pre_auth_session_id = pre_auth_session_id
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.codes = codes
        self.email = email
        self.phone_number = phone_number


class CreateAndSendCustomEmailParameters:
    def __init__(
        self,
        code_life_time: int,
        pre_auth_session_id: str,
        email: str,
        user_input_code: Union[str, None] = None,
        url_with_link_code: Union[str, None] = None,
    ):
        self.email: str = email
        self.code_life_time: int = code_life_time
        self.pre_auth_session_id: str = pre_auth_session_id
        self.user_input_code: Union[str, None] = user_input_code
        self.url_with_link_code: Union[str, None] = url_with_link_code


PasswordlessLoginEmailTemplateVars = CreateAndSendCustomEmailParameters


class CreateAndSendCustomTextMessageParameters:
    def __init__(
        self,
        code_life_time: int,
        pre_auth_session_id: str,
        phone_number: str,
        user_input_code: Union[str, None] = None,
        url_with_link_code: Union[str, None] = None,
    ):
        self.code_life_time: int = code_life_time
        self.pre_auth_session_id: str = pre_auth_session_id
        self.phone_number: str = phone_number
        self.user_input_code: Union[str, None] = user_input_code
        self.url_with_link_code: Union[str, None] = url_with_link_code


PasswordlessLoginSMSTemplateVars = CreateAndSendCustomTextMessageParameters


# Export:
EmailTemplateVars = PasswordlessLoginEmailTemplateVars
SMSTemplateVars = PasswordlessLoginSMSTemplateVars

SMTPOverrideInput = SMTPServiceInterface[EmailTemplateVars]
TwilioOverrideInput = TwilioServiceInterface[SMSTemplateVars]

EmailDeliveryOverrideInput = EmailDeliveryInterface[EmailTemplateVars]
SMSDeliveryOverrideInput = SMSDeliveryInterface[SMSTemplateVars]


class PasswordlessIngredients:
    def __init__(
        self,
        email_delivery: Union[EmailDeliveryIngredient[EmailTemplateVars], None] = None,
        sms_delivery: Union[SMSDeliveryIngredient[SMSTemplateVars], None] = None,
    ):
        self.email_delivery = email_delivery
        self.sms_delivery = sms_delivery
