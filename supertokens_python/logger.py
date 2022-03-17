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
from datetime import datetime, timezone
from os import getenv
from typing import TextIO, Union

from .constants import VERSION

# Configure logger
logger = logging.getLogger()
log_level_str = getenv('LOG_LEVEL', "").lower()
default_log_level = logging.INFO
log_level_dict = {"debug": logging.DEBUG, "info": logging.INFO}
logger.setLevel(log_level_dict.get(log_level_str, default_log_level))


def _get_log_timestamp():
    return datetime.now(timezone.utc).isoformat()


class CustomStreamHandler(logging.StreamHandler):  # type: ignore
    def __init__(self, stream: Union[TextIO, None] = None):
        super().__init__(stream)  # type: ignore
        self.last = .0

    def transform(self, record: logging.LogRecord) -> None:
        record.msg = json.dumps({
            "t": _get_log_timestamp(),
            "sdkVer": VERSION,
            "message": record.msg,
            "file": f'{record.pathname}:{record.lineno}'
        })

        # Adding relative difference wrt the prev log
        try:
            last = self.last
        except AttributeError:
            last = record.relativeCreated

        delta = datetime.fromtimestamp(record.relativeCreated / 1000.0) - datetime.fromtimestamp(last / 1000.0)
        record.relative = f"{(delta.seconds + delta.microseconds / 1000000.0):.2f}"  # type: ignore
        self.last = record.relativeCreated

    def emit(self, record: logging.LogRecord):
        self.transform(record)
        return super().emit(record)


# Add stream handler and format
streamHandler = CustomStreamHandler()
streamFormatter = logging.Formatter("com.supertokens {message} +{relative}ms", style="{")
streamHandler.setFormatter(streamFormatter)
logger.addHandler(streamHandler)
