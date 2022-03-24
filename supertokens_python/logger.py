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
from typing import TextIO, Union

from .constants import VERSION

NAMESPACE = "com.supertokens"
DEBUG_ENV_VAR = "SUPERTOKENS_DEBUG"

supertokens_dir = path.dirname(__file__)

# Configure logger
logger = logging.getLogger(NAMESPACE)
log_level_str = getenv(DEBUG_ENV_VAR, "").lower()
if log_level_str == "1":
    logger.setLevel(logging.DEBUG)


def _get_log_timestamp() -> str:
    return datetime.utcnow().isoformat()[:-3] + "Z"


class CustomStreamHandler(logging.StreamHandler):  # type: ignore
    def __init__(self, stream: Union[TextIO, None] = None):
        super().__init__(stream)  # type: ignore
        # self.last stores the last log timestamp and is used to calculate the
        # time difference between two consecutive logs.
        self.last = .0

    def emit(self, record: logging.LogRecord):
        relative_path = path.relpath(record.pathname, supertokens_dir)

        record.msg = json.dumps({
            "t": _get_log_timestamp(),
            "sdkVer": VERSION,
            "message": record.msg,
            "file": f'{relative_path}:{record.lineno}'
        })

        # Storing relative time difference difference wrt the prev log (in record.relative attribute)
        try:
            last = self.last
        except AttributeError:
            last = record.relativeCreated

        delta = datetime.fromtimestamp(record.relativeCreated / 1000.0) - datetime.fromtimestamp(last / 1000.0)
        record.relative = f"{(delta.seconds + delta.microseconds / 1000000.0):.2f}"  # type: ignore
        self.last = record.relativeCreated

        return super().emit(record)


# Add stream handler and format
streamHandler = CustomStreamHandler()
streamFormatter = logging.Formatter("{name} {message} +{relative}ms", style="{")
streamHandler.setFormatter(streamFormatter)
logger.addHandler(streamHandler)


# The debug logger can be used like this:
# log_debug_message("Hello")
# Output log format:
# com.supertokens {"t": "2022-03-24T06:28:33.659Z", "sdkVer": "0.5.1", "message": "Hello", "file": "logger.py:73"} +0.01ms

# Export logger.debug as log_debug_message function
log_debug_message = logger.debug
