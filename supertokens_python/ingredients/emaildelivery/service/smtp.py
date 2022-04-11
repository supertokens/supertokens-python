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

from ..types import EmailDeliveryInterface

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


class TypeInputSendRawEmailFrom:
    def __init__(self, name: str, email: str) -> None:
        self.name = name
        self.email = email


class TypeGetContentInput(Generic[_T]):
    user_context: Dict[str, Any]


class ServiceInterface(ABC, Generic[_T]):
    @abstractmethod
    async def send_raw_email(self,
                             get_content_result: GetContentResult,
                             config_from: TypeInputSendRawEmailFrom,
                             user_context: Dict[str, Any]
                             ) -> None:
        pass

    @abstractmethod
    def get_content(self, input: _T, user_context: Dict[str, Any]) -> GetContentResult:
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

    def send_email(self, config_from: TypeInputSendRawEmailFrom, get_content_result: GetContentResult, user_context: Dict[str, Any]) -> None:
        print(config_from)
        try:
            smtp = smtplib.SMTP(self.smtpSettings.host, self.smtpSettings.port)
            smtp.starttls()
            if self.smtpSettings.auth:
                smtp.login(self.smtpSettings.auth.user, self.smtpSettings.auth.password)

            smtp.sendmail(config_from.email, get_content_result.to_email, get_content_result.body)
            smtp.quit()
        except Exception as _:
            pass


TypeGetDefaultEmailServiceImpl = Callable[[Transporter, TypeInputSendRawEmailFrom], ServiceInterface[_T]]

class SMTPEmailDeliveryImplementation(EmailDeliveryInterface[_T]):
    def __init__(self, service_impl: ServiceInterface[_T], send_raw_email_from: TypeInputSendRawEmailFrom) -> None:
        self.service_impl = service_impl
        self.send_raw_email_from = send_raw_email_from

    async def send_email(self, email_input: _T, user_context: Dict[str, Any]) -> None:
        content = self.service_impl.get_content(email_input, user_context)
        await self.service_impl.send_raw_email(content, self.send_raw_email_from, user_context)


def getEmailServiceImplementation(
    config: EmailDeliverySMTPConfig[_T],
    getDefaultEmailServiceImplementation: TypeGetDefaultEmailServiceImpl[_T]
) -> ServiceInterface[_T]:

    # smtp_server = smtplib.SMTP_SSL(config.smtpSettings.host, config.smtpSettings.port)
    # smtp_server.ehlo()
    # if config.smtpSettings.auth:
    #     smtp_server.login(config.smtpSettings.auth.user, config.smtpSettings.auth.password)

    transporter = Transporter(config.smtpSettings)

    # partial_smtp = partial(smtp_server.sendmail, from_addr=config.smtpSettings.email_from.email)

    send_raw_email_from = TypeInputSendRawEmailFrom(
        config.smtpSettings.email_from.name,
        config.smtpSettings.email_from.email
    )

    default_impl = getDefaultEmailServiceImplementation(transporter, send_raw_email_from)
    service_impl = default_impl if config.override is None else config.override(default_impl)

    # emi = SMTPEmailDeliveryImplementation(, send_raw_email_from)

    return service_impl

    # partial_smtp(to_addrs=config.smtpSettings.email_from.email, msg=email_text)
    # smtp_server.close()

    # input_send_raw_email = TypeInputSendRawEmailFrom(name=config_from['name'], email=config_from['email'])
    # default_impl = getDefaultEmailServiceImplementation(partial_smtp, input_send_raw_email)
    # impl = config.override if config.override is not None else default_impl

# smtp_service_config = SMTPServiceConfig(
#     host='0.0.0.0',
#     email_from=SMTPServiceConfigFrom(name='VRAI Labs', email='vrailabs@gmail.com'),
#     port=587,
# )
