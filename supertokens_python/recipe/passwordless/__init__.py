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
from typing import Any, Awaitable, Callable, Dict, Union

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

from .recipe import PasswordlessRecipe
from .utils import ContactEmailOrPhoneConfig  # type: ignore
from .utils import ContactPhoneOnlyConfig  # type: ignore
from .utils import CreateAndSendCustomEmailParameters  # type: ignore
from .utils import CreateAndSendCustomTextMessageParameters  # type: ignore
from .utils import PhoneOrEmailInput  # type: ignore
from .utils import ContactConfig, ContactEmailOnlyConfig  # type: ignore
from .utils import OverrideConfig as InputOverrideConfig


def init(contact_config: ContactConfig,
         flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
         override: Union[InputOverrideConfig, None] = None,
         get_link_domain_and_path: Union[Callable[[
             PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None] = None,
         get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = None):
    return PasswordlessRecipe.init(contact_config,
                                   flow_type,
                                   override,
                                   get_link_domain_and_path,
                                   get_custom_user_input_code)
