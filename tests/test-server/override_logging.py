from typing import Any, Dict, List, Set, Union
import time

from httpx import Response

from supertokens_python.framework.flask.flask_request import FlaskRequest
from supertokens_python.types import RecipeUserId

override_logs: List[Dict[str, Any]] = []


def reset_override_logs():
    global override_logs
    override_logs = []


def get_override_logs():
    return override_logs


def log_override_event(name: str, log_type: str, data: Any):
    override_logs.append(
        {
            "t": int(time.time() * 1000),
            "type": log_type,
            "name": name,
            "data": transform_logged_data(data),
        }
    )


def transform_logged_data(data: Any, visited: Union[Set[Any], None] = None) -> Any:
    if isinstance(data, dict):
        return {k: transform_logged_data(v, visited) for k, v in data.items()}  # type: ignore
    if isinstance(data, list):
        return [transform_logged_data(v, visited) for v in data]  # type: ignore
    if isinstance(data, tuple):
        return tuple(transform_logged_data(v, visited) for v in data)  # type: ignore

    if isinstance(data, FlaskRequest):
        return "FlaskRequest"
    if isinstance(data, Response):
        return "Response"
    if isinstance(data, RecipeUserId):
        return data.get_as_string()

    return data
