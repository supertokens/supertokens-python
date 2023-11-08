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
from json import JSONDecodeError
from os import environ
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Tuple

from httpx import AsyncClient, ConnectTimeout, NetworkError, Response

from .constants import (
    API_KEY_HEADER,
    API_VERSION,
    API_VERSION_HEADER,
    RID_KEY_HEADER,
    SUPPORTED_CDI_VERSIONS,
    RATE_LIMIT_STATUS_CODE,
)
from .normalised_url_path import NormalisedURLPath

if TYPE_CHECKING:
    from .supertokens import Host

from typing import List, Set, Union

from .exceptions import raise_general_exception
from .process_state import AllowedProcessStates, ProcessState
from .utils import find_max_version, is_4xx_error, is_5xx_error
from sniffio import AsyncLibraryNotFoundError
from supertokens_python.async_to_sync_wrapper import create_or_get_event_loop


class Querier:
    __init_called = False
    __hosts: List[Host] = []
    __api_key: Union[None, str] = None
    api_version = None
    __last_tried_index: int = 0
    __hosts_alive_for_testing: Set[str] = set()
    network_interceptor: Optional[
        Callable[
            [
                str,
                str,
                Dict[str, Any],
                Optional[Dict[str, Any]],
                Optional[Dict[str, Any]],
                Optional[Dict[str, Any]],
            ],
            Tuple[
                str,
                str,
                Dict[str, Any],
                Optional[Dict[str, Any]],
                Optional[Dict[str, Any]],
            ],
        ]
    ] = None

    def __init__(self, hosts: List[Host], rid_to_core: Union[None, str] = None):
        self.__hosts = hosts
        self.__rid_to_core = None
        if rid_to_core is not None:
            self.__rid_to_core = rid_to_core

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        Querier.__init_called = False

    @staticmethod
    def get_hosts_alive_for_testing():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        return Querier.__hosts_alive_for_testing

    async def api_request(
        self,
        url: str,
        method: str,
        attempts_remaining: int,
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        if attempts_remaining == 0:
            raise_general_exception("Retry request failed")

        try:
            async with AsyncClient() as client:
                if method == "GET":
                    return await client.get(url, *args, **kwargs)  # type: ignore
                if method == "POST":
                    return await client.post(url, *args, **kwargs)  # type: ignore
                if method == "PUT":
                    return await client.put(url, *args, **kwargs)  # type: ignore
                if method == "DELETE":
                    return await client.delete(url, *args, **kwargs)  # type: ignore
                raise Exception("Shouldn't come here")
        except AsyncLibraryNotFoundError:
            # Retry
            loop = create_or_get_event_loop()
            return loop.run_until_complete(
                self.api_request(url, method, attempts_remaining - 1, *args, **kwargs)
            )

    async def get_api_version(self):
        if Querier.api_version is not None:
            return Querier.api_version

        ProcessState.get_instance().add_state(
            AllowedProcessStates.CALLING_SERVICE_IN_GET_API_VERSION
        )

        async def f(url: str, method: str) -> Response:
            headers = {}
            if Querier.__api_key is not None:
                headers = {API_KEY_HEADER: Querier.__api_key}
            return await self.api_request(url, method, 2, headers=headers)

        response = await self.__send_request_helper(
            NormalisedURLPath(API_VERSION), "GET", f, len(self.__hosts)
        )
        cdi_supported_by_server = response["versions"]
        api_version = find_max_version(cdi_supported_by_server, SUPPORTED_CDI_VERSIONS)

        if api_version is None:
            raise_general_exception(
                "The running SuperTokens core version is not compatible with this python "
                "SDK. Please visit https://supertokens.io/docs/community/compatibility-table "
                "to find the right versions"
            )

        Querier.api_version = api_version
        return Querier.api_version

    @staticmethod
    def get_instance(rid_to_core: Union[str, None] = None):
        if (not Querier.__init_called) or (Querier.__hosts is None):
            raise Exception(
                "Please call the supertokens.init function before using SuperTokens"
            )
        return Querier(Querier.__hosts, rid_to_core)

    @staticmethod
    def init(
        hosts: List[Host],
        api_key: Union[str, None] = None,
        network_interceptor: Optional[
            Callable[
                [
                    str,
                    str,
                    Dict[str, Any],
                    Optional[Dict[str, Any]],
                    Optional[Dict[str, Any]],
                    Optional[Dict[str, Any]],
                ],
                Tuple[
                    str,
                    str,
                    Dict[str, Any],
                    Optional[Dict[str, Any]],
                    Optional[Dict[str, Any]],
                ],
            ]
        ] = None,
    ):
        if not Querier.__init_called:
            Querier.__init_called = True
            Querier.__hosts = hosts
            Querier.__api_key = api_key
            Querier.api_version = None
            Querier.__last_tried_index = 0
            Querier.__hosts_alive_for_testing = set()
            Querier.network_interceptor = network_interceptor

    async def __get_headers_with_api_version(self, path: NormalisedURLPath):
        headers = {API_VERSION_HEADER: await self.get_api_version()}
        if Querier.__api_key is not None:
            headers = {**headers, API_KEY_HEADER: Querier.__api_key}
        if path.is_a_recipe_path() and self.__rid_to_core is not None:
            headers = {**headers, RID_KEY_HEADER: self.__rid_to_core}
        return headers

    async def send_get_request(
        self,
        path: NormalisedURLPath,
        params: Union[Dict[str, Any], None],
        user_context: Union[Dict[str, Any], None],
    ) -> Dict[str, Any]:
        if params is None:
            params = {}

        async def f(url: str, method: str) -> Response:
            headers = await self.__get_headers_with_api_version(path)
            nonlocal params
            if Querier.network_interceptor is not None:
                (
                    url,
                    method,
                    headers,
                    params,
                    _,
                ) = Querier.network_interceptor(  # pylint:disable=not-callable
                    url, method, headers, params, {}, user_context
                )

            return await self.api_request(
                url,
                method,
                2,
                headers=headers,
                params=params,
            )

        return await self.__send_request_helper(path, "GET", f, len(self.__hosts))

    async def send_post_request(
        self,
        path: NormalisedURLPath,
        data: Union[Dict[str, Any], None],
        user_context: Union[Dict[str, Any], None],
        test: bool = False,
    ) -> Dict[str, Any]:
        if data is None:
            data = {}

        if (
            ("SUPERTOKENS_ENV" in environ)
            and (environ["SUPERTOKENS_ENV"] == "testing")
            and test
        ):
            return data

        headers = await self.__get_headers_with_api_version(path)
        headers["content-type"] = "application/json; charset=utf-8"

        async def f(url: str, method: str) -> Response:
            nonlocal headers, data
            if Querier.network_interceptor is not None:
                (
                    url,
                    method,
                    headers,
                    _,
                    data,
                ) = Querier.network_interceptor(  # pylint:disable=not-callable
                    url, method, headers, {}, data, user_context
                )
            return await self.api_request(
                url,
                method,
                2,
                headers=headers,
                json=data,
            )

        return await self.__send_request_helper(path, "POST", f, len(self.__hosts))

    async def send_delete_request(
        self,
        path: NormalisedURLPath,
        params: Union[Dict[str, Any], None],
        user_context: Union[Dict[str, Any], None],
    ) -> Dict[str, Any]:
        if params is None:
            params = {}

        async def f(url: str, method: str) -> Response:
            headers = await self.__get_headers_with_api_version(path)
            nonlocal params
            if Querier.network_interceptor is not None:
                (
                    url,
                    method,
                    headers,
                    params,
                    _,
                ) = Querier.network_interceptor(  # pylint:disable=not-callable
                    url, method, headers, params, {}, user_context
                )
            return await self.api_request(
                url,
                method,
                2,
                headers=headers,
                params=params,
            )

        return await self.__send_request_helper(path, "DELETE", f, len(self.__hosts))

    async def send_put_request(
        self,
        path: NormalisedURLPath,
        data: Union[Dict[str, Any], None],
        user_context: Union[Dict[str, Any], None],
    ) -> Dict[str, Any]:
        if data is None:
            data = {}

        headers = await self.__get_headers_with_api_version(path)
        headers["content-type"] = "application/json; charset=utf-8"

        async def f(url: str, method: str) -> Response:
            nonlocal headers, data
            if Querier.network_interceptor is not None:
                (
                    url,
                    method,
                    headers,
                    _,
                    data,
                ) = Querier.network_interceptor(  # pylint:disable=not-callable
                    url, method, headers, {}, data, user_context
                )
            return await self.api_request(url, method, 2, headers=headers, json=data)

        return await self.__send_request_helper(path, "PUT", f, len(self.__hosts))

    def get_all_core_urls_for_path(self, path: str) -> List[str]:
        if self.__hosts is None:
            return []

        normalized_path = NormalisedURLPath(path)

        result: List[str] = []

        for h in self.__hosts:
            current_domain = h.domain.get_as_string_dangerous()
            current_base_path = h.base_path.get_as_string_dangerous()

            result.append(
                current_domain
                + current_base_path
                + normalized_path.get_as_string_dangerous()
            )
        return result

    async def __send_request_helper(
        self,
        path: NormalisedURLPath,
        method: str,
        http_function: Callable[[str, str], Awaitable[Response]],
        no_of_tries: int,
        retry_info_map: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        if no_of_tries == 0:
            raise_general_exception("No SuperTokens core available to query")

        try:
            current_host_domain = self.__hosts[
                Querier.__last_tried_index
            ].domain.get_as_string_dangerous()
            current_host_base_path = self.__hosts[
                Querier.__last_tried_index
            ].base_path.get_as_string_dangerous()
            current_host: str = current_host_domain + current_host_base_path
            Querier.__last_tried_index += 1
            Querier.__last_tried_index %= len(self.__hosts)
            url = current_host + path.get_as_string_dangerous()

            max_retries = 5

            if retry_info_map is None:
                retry_info_map = {}

            if retry_info_map.get(url) is None:
                retry_info_map[url] = max_retries

            ProcessState.get_instance().add_state(
                AllowedProcessStates.CALLING_SERVICE_IN_REQUEST_HELPER
            )
            response = await http_function(url, method)
            if ("SUPERTOKENS_ENV" in environ) and (
                environ["SUPERTOKENS_ENV"] == "testing"
            ):
                Querier.__hosts_alive_for_testing.add(current_host)

            if response.status_code == RATE_LIMIT_STATUS_CODE:
                retries_left = retry_info_map[url]

                if retries_left > 0:
                    retry_info_map[url] = retries_left - 1

                    attempts_made = max_retries - retries_left
                    delay = (10 + attempts_made * 250) / 1000

                    await asyncio.sleep(delay)
                    return await self.__send_request_helper(
                        path, method, http_function, no_of_tries, retry_info_map
                    )

            if is_4xx_error(response.status_code) or is_5xx_error(response.status_code):  # type: ignore
                raise_general_exception(
                    "SuperTokens core threw an error for a "
                    + method
                    + " request to path: "
                    + path.get_as_string_dangerous()
                    + " with status code: "
                    + str(response.status_code)
                    + " and message: "
                    + response.text  # type: ignore
                )

            res: Dict[str, Any] = {"_headers": dict(response.headers)}

            try:
                res.update(response.json())
            except JSONDecodeError:
                res["_text"] = response.text

            return res

        except (ConnectionError, NetworkError, ConnectTimeout) as _:
            return await self.__send_request_helper(
                path, method, http_function, no_of_tries - 1, retry_info_map
            )
        except Exception as e:
            raise_general_exception(e)
