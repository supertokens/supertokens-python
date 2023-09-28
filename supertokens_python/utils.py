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

import json
import threading
import warnings
from base64 import urlsafe_b64decode, urlsafe_b64encode, b64encode, b64decode
from math import floor
from re import fullmatch
from time import time
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    TypeVar,
    Union,
    Optional,
)
from urllib.parse import urlparse

from httpx import HTTPStatusError, Response
from tldextract import extract  # type: ignore

from supertokens_python.framework.django.framework import DjangoFramework
from supertokens_python.framework.fastapi.framework import FastapiFramework
from supertokens_python.framework.flask.framework import FlaskFramework
from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse
from supertokens_python.logger import log_debug_message

from .constants import ERROR_MESSAGE_KEY, RID_KEY_HEADER
from .exceptions import raise_general_exception
from .types import MaybeAwaitable

_T = TypeVar("_T")

if TYPE_CHECKING:
    pass


FRAMEWORKS = {
    "fastapi": FastapiFramework(),
    "flask": FlaskFramework(),
    "django": DjangoFramework(),
}


def is_an_ip_address(ip_address: str) -> bool:
    return (
        fullmatch(
            r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|["
            r"01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            ip_address,
        )
        is not None
    )


def normalise_http_method(method: str) -> str:
    return method.lower()


def get_rid_from_header(request: BaseRequest) -> Union[str, None]:
    return get_header(request, RID_KEY_HEADER)


def get_header(request: BaseRequest, key: str) -> Union[str, None]:
    return request.get_header(key)


def find_max_version(versions_1: List[str], versions_2: List[str]) -> Union[str, None]:
    versions = list(set(versions_1) & set(versions_2))
    if len(versions) == 0:
        return None

    max_v = versions[0]
    for i in range(1, len(versions)):
        version = versions[i]
        max_v = _get_max_version(max_v, version)

    return max_v


def is_version_gte(version: str, minimum_version: str) -> bool:
    return _get_max_version(version, minimum_version) == version


def _get_max_version(v1: str, v2: str) -> str:
    v1_split = v1.split(".")
    v2_split = v2.split(".")
    max_loop = min(len(v1_split), len(v2_split))

    for i in range(max_loop):
        if int(v1_split[i]) > int(v2_split[i]):
            return v1
        if int(v2_split[i]) > int(v1_split[i]):
            return v2

    if len(v1_split) > len(v2_split):
        return v1

    return v2


def is_4xx_error(status_code: int) -> bool:
    return status_code // 100 == 4


def is_5xx_error(status_code: int) -> bool:
    return status_code // 100 == 5


def send_non_200_response(
    body: Dict[str, Any], status_code: int, response: BaseResponse
) -> BaseResponse:
    if status_code < 300:
        raise_general_exception("Calling sendNon200Response with status code < 300")
    log_debug_message(
        "Sending response to client with status code: %s", str(status_code)
    )
    response.set_status_code(status_code)
    response.set_json_content(content=body)
    return response


def send_non_200_response_with_message(
    message: str, status_code: int, response: BaseResponse
) -> BaseResponse:
    return send_non_200_response({ERROR_MESSAGE_KEY: message}, status_code, response)


def send_unauthorised_access_response(response: BaseResponse) -> BaseResponse:
    return send_non_200_response_with_message("Unauthorised access", 401, response)


def send_200_response(
    data_json: Dict[str, Any], response: BaseResponse
) -> BaseResponse:
    log_debug_message("Sending response to client with status code: 200")
    response.set_json_content(data_json)
    response.set_status_code(200)
    return response


def get_timestamp_ms() -> int:
    return int(time() * 1000)


def utf_base64encode(s: str, urlsafe: bool) -> str:
    if urlsafe:
        return urlsafe_b64encode(s.encode("utf-8")).decode("utf-8")

    return b64encode(s.encode("utf-8")).decode("utf-8")


def utf_base64decode(s: str, urlsafe: bool) -> str:
    # Adding extra "==" based on
    # https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
    # Otherwise it can raise "incorrect padding" error
    if urlsafe:
        return urlsafe_b64decode(s.encode("utf-8") + b"==").decode("utf-8")

    return b64decode(s.encode("utf-8")).decode("utf-8")


def get_filtered_list(func: Callable[[_T], bool], given_list: List[_T]) -> List[_T]:
    return list(filter(func, given_list))


def find_first_occurrence_in_list(
    condition: Callable[[_T], bool], given_list: List[_T]
) -> Union[_T, None]:
    for item in given_list:
        if condition(item):
            return item
    return None


def frontend_has_interceptor(request: BaseRequest) -> bool:
    return get_rid_from_header(request) is not None


def deprecated_warn(msg: str):
    warnings.warn(msg, DeprecationWarning, stacklevel=2)


def handle_httpx_client_exceptions(
    e: Exception, input_: Union[Dict[str, Any], None] = None
):
    if isinstance(e, HTTPStatusError) and isinstance(e.response, Response):  # type: ignore
        res = e.response  # type: ignore
        log_debug_message("Error status: %s", res.status_code)  # type: ignore
        log_debug_message("Error response: %s", res.json())
    else:
        log_debug_message("Error: %s", str(e))

    if input_ is not None:
        log_debug_message("Logging the input:")
        log_debug_message("%s", json.dumps(input_))


def humanize_time(ms: int) -> str:
    t = floor(ms / 1000)
    suffix = ""

    if t < 60:
        if t > 1:
            suffix = "s"
        time_str = f"{t} second{suffix}"
    elif t < 3600:
        m = floor(t / 60)
        if m > 1:
            suffix = "s"
        time_str = f"{m} minute{suffix}"
    else:
        h = floor(t / 360) / 10
        if h > 1:
            suffix = "s"
        if h % 1 == 0:
            h = int(h)
        time_str = f"{h} hour{suffix}"

    return time_str


def set_request_in_user_context_if_not_defined(
    user_context: Optional[Dict[str, Any]], request: BaseRequest
) -> Dict[str, Any]:
    if user_context is None:
        user_context = {}

    if "_default" not in user_context:
        user_context["_default"] = {}

    if isinstance(user_context["_default"], dict):
        user_context["_default"]["request"] = request

    return user_context


def default_user_context(request: BaseRequest) -> Dict[str, Any]:
    return set_request_in_user_context_if_not_defined({}, request)


async def resolve(obj: MaybeAwaitable[_T]) -> _T:
    """Returns value or value of awaitable object passed"""
    if isinstance(obj, Awaitable):
        return await obj  # type: ignore
    return obj  # type: ignore


def get_top_level_domain_for_same_site_resolution(url: str) -> str:
    url_obj = urlparse(url)
    hostname = url_obj.hostname

    if hostname is None:
        raise Exception("Should not come here")

    if hostname.startswith("localhost") or is_an_ip_address(hostname):
        return "localhost"

    parsed_url: Any = extract(hostname, include_psl_private_domains=True)
    if parsed_url.domain == "":  # type: ignore
        # We need to do this because of https://github.com/supertokens/supertokens-python/issues/394
        if hostname.endswith(".amazonaws.com") and parsed_url.suffix == hostname:
            return hostname

        raise Exception(
            "Please make sure that the apiDomain and websiteDomain have correct values"
        )

    return parsed_url.domain + "." + parsed_url.suffix  # type: ignore


class RWMutex:
    def __init__(self):
        self._lock = threading.Lock()
        self._readers = threading.Condition(self._lock)
        self._writers = threading.Condition(self._lock)
        self._reader_count = 0
        self._writer_count = 0

    def lock(self):
        with self._lock:
            while self._writer_count > 0 or self._reader_count > 0:
                self._writers.wait()
            self._writer_count += 1

    def unlock(self):
        with self._lock:
            self._writer_count -= 1
            self._readers.notify_all()
            self._writers.notify_all()

    def r_lock(self):
        with self._lock:
            while self._writer_count > 0:
                self._readers.wait()
            self._reader_count += 1

    def r_unlock(self):
        with self._lock:
            self._reader_count -= 1
            if self._reader_count == 0:
                self._writers.notify_all()


class RWLockContext:
    def __init__(self, mutex: RWMutex, read: bool = True):
        self.mutex = mutex
        self.read = read

    def __enter__(self):
        if self.read:
            self.mutex.r_lock()
        else:
            self.mutex.lock()

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any):
        if self.read:
            self.mutex.r_unlock()
        else:
            self.mutex.unlock()

        if exc_type is not None:
            raise exc_type(exc_value).with_traceback(traceback)


def normalise_email(email: str) -> str:
    return email.strip().lower()
