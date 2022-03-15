import json
import logging
import logging.config
from datetime import datetime
from os import getenv
from typing import Any, Dict, Optional

from constants import VERSION


class LoggerCodes:
    ApiResponse = 1

# Setup level names to match with other st libraries
level_maps = {
    logging.DEBUG: "debug",
    logging.INFO: "info",
    logging.ERROR: "error",
}
for level, alias in level_maps.items():
    logging.addLevelName(level, alias)

# Configure logger
logger = logging.getLogger("com.supertokens")
debug = (getenv('LOG_LEVEL', 'info').lower() == "debug")
logger.setLevel(logging.DEBUG if debug else logging.INFO)


# Add stream handler
streamHandler = logging.StreamHandler()
stream_formatter = logging.Formatter("{name}:{levelname} {message}", style="{")
streamHandler.setFormatter(stream_formatter)
logger.addHandler(streamHandler)


def _get_iso_date():
    return datetime.now().isoformat()


def _log_message(
    log_level: int, extra_params: Optional[Dict[str, Any]] = None
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
    code_to_msg: Dict[int, str] = {
        LoggerCodes.ApiResponse: f"API replied with status {item}"
    }
    _debug_logger_helper(code, code_to_msg[code])

