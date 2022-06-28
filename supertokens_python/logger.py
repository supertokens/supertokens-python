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

import json
import logging
from datetime import datetime
from os import getenv, path
from typing import Union

from .constants import VERSION

NAMESPACE = "com.supertokens"
DEBUG_ENV_VAR = "SUPERTOKENS_DEBUG"

supertokens_dir = path.dirname(__file__)

# Configure logger
_logger = logging.getLogger(NAMESPACE)
debug_env = getenv(DEBUG_ENV_VAR, "").lower()
if debug_env == "1":
    _logger.setLevel(logging.DEBUG)


def _get_log_timestamp() -> str:
    return datetime.utcnow().isoformat()[:-3] + "Z"


class CustomStreamHandler(logging.StreamHandler):  # type: ignore
    def emit(self, record: logging.LogRecord):
        relative_path = path.relpath(record.pathname, supertokens_dir)

        record.msg = json.dumps(
            {
                "t": _get_log_timestamp(),
                "sdkVer": VERSION,
                "message": record.msg,
                "file": f"{relative_path}:{record.lineno}",
            }
        )

        return super().emit(record)


# Add stream handler and format
streamHandler = CustomStreamHandler()
streamFormatter = logging.Formatter("{name} {message}\n", style="{")
streamHandler.setFormatter(streamFormatter)
_logger.addHandler(streamHandler)


# The debug logger can be used like this:
# log_debug_message("Hello")
# Output log format:
# com.supertokens {"t": "2022-03-24T06:28:33.659Z", "sdkVer": "0.5.1", "message": "Hello", "file": "logger.py:73"}

# Export logger.debug as log_debug_message function
log_debug_message = _logger.debug


def get_maybe_none_as_str(o: Union[str, None]) -> str:
    if o is None:
        return "None"
    return o
