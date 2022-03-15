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
import logging.config
from datetime import datetime
from os import getenv
from typing import Any, Callable, Dict, Union

from .constants import VERSION


class LoggerCodes:
    API_RESPONSE = 1

# Setup level names to match log output with other st libraries
# If this step is removed, the output will print 'DEBUG' instead of 'debug'
level_maps = {
    logging.DEBUG: "debug",
    logging.INFO: "info",
}
for level, alias in level_maps.items():
    logging.addLevelName(level, alias)

# Configure logger
logger = logging.getLogger("com.supertokens")
log_level = getenv('LOG_LEVEL', "").lower()
map = {"debug": logging.DEBUG, "info": logging.INFO}
logger.setLevel(map.get(log_level, logging.INFO))

# Add stream handler and format
streamHandler = logging.StreamHandler()
stream_formatter = logging.Formatter("{name}:{levelname} {message}", style="{")
streamHandler.setFormatter(stream_formatter)
logger.addHandler(streamHandler)


def _get_iso_date():
    return datetime.now


def _log_message(
    log_level: int, extra_params: Union[None, Dict[str, Any]] = None
):
    if extra_params is None:
        extra_params = {}

    json_msg = json.dumps({
        "t": _get_iso_date(),
        "sdkVer": VERSION,
        **extra_params,
    })

    if log_level == logging.INFO:
        logger.info(json_msg)
    elif log_level == logging.DEBUG:
        logger.debug(json_msg)


def _debug_logger_helper(debug_code: int, message: str):
    _log_message(logging.DEBUG, {"message": message, "debugCode": debug_code})


def info_logger(message: str):
    _log_message(logging.INFO, {"message": message})


def debug_logger(item: str, code: int):
    def api_response(item: str) -> str:
        return f"API replied with status {item}"
    
    code_to_msg: Dict[int, Callable[..., str]] = {
        LoggerCodes.API_RESPONSE: api_response
    }
    _debug_logger_helper(code, code_to_msg[code](item))

