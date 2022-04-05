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


from ..types import EmailDeliveryInterface
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Generic, TypedDict, TypeVar, Union

_T = TypeVar('_T')


class SMTPServiceConfigAuth:
    user: str
    password: str


class SMTPServiceConfigFrom:
    name: str
    email: str


class SMTPServiceConfig:
    def __init__(
        self,
        host: str,
        email_from: SMTPServiceConfigFrom,
        port: int,
        secure: Union[bool, None] = None,
        auth: Union[SMTPServiceConfigAuth, None] = None
    ) -> None:
        self.host = host
        self.email_from = email_from
        self.port = port
        self.secure = secure
        self.auth = auth


class GetContentResult(TypedDict):
    body: str
    subject: str
    toEmail: str


class TypeInputSendRawEmailFrom:
    name: str
    email: str

    def __init__(self, name: str, email: str) -> None:
        self.name = name
        self.email = email


class TypeInputSendRawEmail(GetContentResult):
    user_context: Dict[str, Any]
    config_from: TypeInputSendRawEmailFrom

# TypeInputSendRawEmail: Union[GetContentResult, Dict[str, Any], TypeInputSendRawEmailFrom]


class TypeGetContentInput(Generic[_T]):
    user_context: Dict[str, Any]


class ServiceInterface(ABC, Generic[_T]):
    @abstractmethod
    def send_raw_email(self, input: TypeInputSendRawEmail):
        pass

    @abstractmethod
    def get_content(self, input: TypeGetContentInput[_T]):
        pass


class TypeInput(Generic[_T]):
    smtpSettings: SMTPServiceConfig

    @abstractmethod
    def override(self, oi: ServiceInterface[_T]) -> ServiceInterface[_T]:
        pass


class Transporter():
    pass


def createTransport(_) -> Transporter:
    return Transporter()


TypeGetDefaultEmailServiceImpl = Callable[[Transporter, TypeInputSendRawEmailFrom], ServiceInterface[_T]]


def getEmailServiceImplementation(
    config: TypeInput[_T],
    getDefaultEmailServiceImplementation: TypeGetDefaultEmailServiceImpl[_T]
) -> EmailDeliveryInterface[_T]:
    transporter = createTransport({'host': ...})

    config_from = config.smtpSettings['from']
    input_send_raw_email = TypeInputSendRawEmailFrom(name=config_from['name'], email=config_from['email'])
    default_impl = getDefaultEmailServiceImplementation(transporter, input_send_raw_email)
    # impl = config.override if config.override is not None else default_impl

    return default_impl
