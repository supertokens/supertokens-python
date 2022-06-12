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


class EmailDeliveryInterface(ABC, Generic[_T]):
    @abstractmethod
    async def send_email(self, input_: _T, user_context: Dict[str, Any]) -> None:
        pass


class EmailDeliveryConfig(ABC, Generic[_T]):
    def __init__(
        self, service: Union[EmailDeliveryInterface[_T], None] = None,
        override: Union[Callable[[EmailDeliveryInterface[_T]], EmailDeliveryInterface[_T]], None] = None,
    ) -> None:
        self.service = service
        self.override = override


class EmailDeliveryConfigWithService(ABC, Generic[_T]):
    def __init__(
        self, service: EmailDeliveryInterface[_T],
        override: Union[Callable[[EmailDeliveryInterface[_T]], EmailDeliveryInterface[_T]], None] = None,
    ) -> None:
        self.service = service
        self.override = override
