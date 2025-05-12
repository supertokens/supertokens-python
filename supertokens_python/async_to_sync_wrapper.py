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

import asyncio
from functools import update_wrapper
from os import getenv
from typing import (
    Any,
    Callable,
    Coroutine,
    Generic,
    TypeVar,
)

from typing_extensions import ParamSpec

Param = ParamSpec("Param")
RetType = TypeVar("RetType", covariant=True)

_T = TypeVar("_T")


def nest_asyncio_enabled():
    return getenv("SUPERTOKENS_NEST_ASYNCIO", "") == "1"


def create_or_get_event_loop() -> asyncio.AbstractEventLoop:
    try:
        return asyncio.get_event_loop()
    except Exception as ex:
        if "There is no current event loop in thread" in str(ex):
            loop = asyncio.new_event_loop()

            if nest_asyncio_enabled():
                import nest_asyncio  # type: ignore

                nest_asyncio.apply(loop)  # type: ignore

            asyncio.set_event_loop(loop)
            return loop
        raise ex


def sync(co: Coroutine[Any, Any, _T]) -> _T:
    loop = create_or_get_event_loop()
    return loop.run_until_complete(co)


class syncify(Generic[Param, RetType]):
    """
    Decorator to allow async functions to be executed synchronously
    using a `sync` attribute.
    """

    def __init__(self, func: Callable[Param, Coroutine[Any, Any, RetType]]):
        update_wrapper(self, func)
        self.func = func

    def __call__(
        self, *args: Param.args, **kwargs: Param.kwargs
    ) -> Coroutine[Any, Any, RetType]:
        return self.func(*args, **kwargs)

    def sync(self, *args: Param.args, **kwargs: Param.kwargs) -> RetType:
        """
        Synchronous version of the decorated function.
        """
        return sync(self.func(*args, **kwargs))
