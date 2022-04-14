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


import smtplib
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Generic, TypeVar, Union

_T = TypeVar('_T')


class SMTPServiceConfigAuth:
    def __init__(self, user: str, password: str) -> None:
        self.user = user
        self.password = password


class SMTPServiceConfigFrom:
    def __init__(self, name: str, email: str) -> None:
        self.name = name
        self.email = email


class SMTPServiceConfig:
    def __init__(
        self, host: str, email_from: SMTPServiceConfigFrom,
        port: int, secure: Union[bool, None] = None,
        auth: Union[SMTPServiceConfigAuth, None] = None
    ) -> None:
        self.host = host
        self.email_from = email_from
        self.port = port
        self.secure = secure
        self.auth = auth


class GetContentResult:
    def __init__(self, body: str, subject: str, to_email: str) -> None:
        self.body = body
        self.subject = subject
        self.to_email = to_email


class ServiceInterface(ABC, Generic[_T]):
    @abstractmethod
    async def send_raw_email(self,
                             get_content_result: GetContentResult,
                             config_from: SMTPServiceConfigFrom,
                             user_context: Dict[str, Any]
                             ) -> None:
        pass

    @abstractmethod
    async def get_content(self, email_input: _T, user_context: Dict[str, Any]) -> GetContentResult:
        pass


class EmailDeliverySMTPConfig(Generic[_T]):
    def __init__(self,
                 smtpSettings: SMTPServiceConfig,
                 override: Union[Callable[[ServiceInterface[_T]], ServiceInterface[_T]], None] = None
                 ) -> None:
        self.smtpSettings = smtpSettings
        self.override = override


class Transporter:
    def __init__(self, smtpSettings: SMTPServiceConfig) -> None:
        self.smtpSettings = smtpSettings

    def send_email(self, config_from: SMTPServiceConfigFrom, get_content_result: GetContentResult,
                   _: Dict[str, Any]) -> None:
        try:
            smtp = smtplib.SMTP(self.smtpSettings.host, self.smtpSettings.port)
            smtp.starttls()
            if self.smtpSettings.auth:
                smtp.login(self.smtpSettings.auth.user, self.smtpSettings.auth.password)

            smtp.sendmail(config_from.email, get_content_result.to_email, get_content_result.body)
            smtp.quit()
        except Exception:
            pass
