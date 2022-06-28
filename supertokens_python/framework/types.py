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
from enum import Enum
from typing import Any, Union

from supertokens_python.framework.request import BaseRequest

frameworks = ["fastapi", "flask", "django"]


class FrameworkEnum(Enum):
    FASTAPI = 1
    FLASK = 2
    DJANGO = 3


class Framework(ABC):
    @abstractmethod
    def wrap_request(self, unwrapped: Any) -> Union[BaseRequest, None]:
        pass
