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
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Generic, TypeVar, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from supertokens_python.ingredients.emaildelivery.services.smtp import Transporter

_T = TypeVar("_T")


class EmailDeliveryInterface(ABC, Generic[_T]):
    @abstractmethod
    async def send_email(self, template_vars: _T, user_context: Dict[str, Any]) -> None:
        pass


class EmailDeliveryConfig(ABC, Generic[_T]):
    def __init__(
        self,
        service: Union[EmailDeliveryInterface[_T], None] = None,
        override: Union[
            Callable[[EmailDeliveryInterface[_T]], EmailDeliveryInterface[_T]], None
        ] = None,
    ) -> None:
        self.service = service
        self.override = override


class EmailDeliveryConfigWithService(ABC, Generic[_T]):
    def __init__(
        self,
        service: EmailDeliveryInterface[_T],
        override: Union[
            Callable[[EmailDeliveryInterface[_T]], EmailDeliveryInterface[_T]], None
        ] = None,
    ) -> None:
        self.service = service
        self.override = override


class SMTPSettingsFrom:
    def __init__(self, name: str, email: str) -> None:
        self.name = name
        self.email = email


class SMTPSettings:
    def __init__(
        self,
        host: str,
        port: int,
        from_: SMTPSettingsFrom,
        password: Union[str, None] = None,
        secure: Union[bool, None] = None,
        username: Union[str, None] = None,
    ) -> None:
        self.host = host
        self.from_ = from_
        self.password = password
        self.port = port
        self.secure = secure
        self.username = username


class EmailContent:
    def __init__(self, body: str, subject: str, to_email: str, is_html: bool) -> None:
        self.body = body
        self.subject = subject
        self.to_email = to_email
        self.is_html = is_html


class SMTPServiceInterface(ABC, Generic[_T]):
    def __init__(self, transporter: Transporter) -> None:
        self.transporter = transporter

    @abstractmethod
    async def send_raw_email(
        self, content: EmailContent, user_context: Dict[str, Any]
    ) -> None:
        pass

    @abstractmethod
    async def get_content(
        self, template_vars: _T, user_context: Dict[str, Any]
    ) -> EmailContent:
        pass
