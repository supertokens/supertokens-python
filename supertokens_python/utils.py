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

import asyncio
from base64 import b64decode, b64encode
from re import fullmatch
from time import time
from typing import (TYPE_CHECKING, Any, Callable, Coroutine, Dict, List,
                    TypeVar, Union)

from supertokens_python.async_to_sync_wrapper import check_event_loop
from supertokens_python.framework.django.framework import DjangoFramework
from supertokens_python.framework.fastapi.framework import FastapiFramework
from supertokens_python.framework.flask.framework import FlaskFramework
from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse

from .constants import ERROR_MESSAGE_KEY, RID_KEY_HEADER
from .exceptions import raise_general_exception

_T = TypeVar("_T")

if TYPE_CHECKING:
    pass


FRAMEWORKS = {
    'fastapi': FastapiFramework(),
    'flask': FlaskFramework(),
    'django': DjangoFramework(),
}


def is_an_ip_address(ip_address: str) -> bool:
    return fullmatch(
        r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|['
        r'01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
        ip_address) is not None


def normalise_http_method(method: str) -> str:
    return method.lower()


def get_rid_from_request(request: BaseRequest) -> Union[str, None]:
    return get_header(request, RID_KEY_HEADER)


def get_header(request: BaseRequest, key: str) -> Union[str, None]:
    return request.get_header(key)


def find_max_version(
        versions_1: List[str], versions_2: List[str]) -> Union[str, None]:
    versions = list(set(versions_1) & set(versions_2))
    if len(versions) == 0:
        return None

    max_v = versions[0]
    for i in range(1, len(versions)):
        version = versions[i]
        max_v = compare_version(max_v, version)

    return max_v


def compare_version(v1: str, v2: str) -> str:
    v1_split = v1.split('.')
    v2_split = v2.split('.')
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


def send_non_200_response(message: str, status_code: int,
                          response: BaseResponse) -> BaseResponse:
    if status_code < 300:
        raise_general_exception(
            'Calling sendNon200Response with status code < 300')
    response.set_status_code(status_code)
    response.set_json_content(content={
        ERROR_MESSAGE_KEY: message
    })
    return response


def send_200_response(
        data_json: Dict[str, Any], response: BaseResponse) -> BaseResponse:
    response.set_json_content(data_json)
    response.set_status_code(200)
    return response


def get_timestamp_ms() -> int:
    return int(time() * 1000)


def utf_base64encode(s: str) -> str:
    return b64encode(s.encode('utf-8')).decode('utf-8')


def utf_base64decode(s: str) -> str:
    return b64decode(s.encode('utf-8')).decode('utf-8')


def get_filtered_list(func: Callable[[_T], bool], given_list: List[_T]) -> List[_T]:
    return list(filter(func, given_list))


def find_first_occurrence_in_list(
        condition: Callable[[_T], bool], given_list: List[_T]) -> Union[_T, None]:
    for item in given_list:
        if condition(item):
            return item
    return None


def execute_in_background(mode: str, func: Callable[[], Coroutine[Any, Any, None]]):
    if mode == 'wsgi':
        check_event_loop()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(func())
    else:
        asyncio.create_task(func())


def frontend_has_interceptor(request: BaseRequest) -> bool:
    return get_rid_from_request(request) is not None
