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
from email.mime.text import MIMEText
from typing import Any, Callable, Dict, Generic, TypeVar, Union

from supertokens_python.logger import log_debug_message

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
    def __init__(self, body: str, subject: str, to_email: str, is_html: bool = True) -> None:
        self.body = body
        self.subject = subject
        self.to_email = to_email
        self.is_html = is_html


class Transporter:
    def __init__(self, smtp_settings: SMTPServiceConfig) -> None:
        self.smtp_settings = smtp_settings

    async def send_email(self, config_from: SMTPServiceConfigFrom, get_content_result: GetContentResult,
                         _: Dict[str, Any]) -> None:
        smtp = smtplib.SMTP(self.smtp_settings.host, self.smtp_settings.port)
        try:
            if self.smtp_settings.secure:
                smtp.starttls()
            if self.smtp_settings.auth:
                smtp.login(self.smtp_settings.auth.user, self.smtp_settings.auth.password)

            if get_content_result.is_html:
                email_content = MIMEText(get_content_result.body, "html")
                email_content["From"] = config_from.email
                email_content["To"] = get_content_result.to_email
                email_content["Subject"] = get_content_result.subject
                smtp.sendmail(config_from.email, get_content_result.to_email, email_content.as_string())
            else:
                smtp.sendmail(config_from.email, get_content_result.to_email, get_content_result.body)

        except Exception as e:
            log_debug_message('Error sending email: %s', e)
        finally:
            smtp.quit()


class ServiceInterface(ABC, Generic[_T]):
    def __init__(self, transporter: Transporter, config_from: SMTPServiceConfigFrom) -> None:
        self.transporter = transporter
        self.config_from = config_from

    @abstractmethod
    async def send_raw_email(self,
                             get_content_result: GetContentResult,
                             user_context: Dict[str, Any]
                             ) -> None:
        pass

    @abstractmethod
    async def get_content(self, email_input: _T) -> GetContentResult:
        pass


class EmailDeliverySMTPConfig(Generic[_T]):
    def __init__(self,
                 smtp_settings: SMTPServiceConfig,
                 override: Union[Callable[[ServiceInterface[_T]], ServiceInterface[_T]], None] = None
                 ) -> None:
        self.smtp_settings = smtp_settings
        self.override = override
