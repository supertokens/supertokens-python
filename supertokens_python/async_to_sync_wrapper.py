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
from os import getenv
from typing import Any, Coroutine, Optional, TypeVar

uvloop_available = False
try:
    import uvloop

    uvloop_available = True
except ImportError:
    ...

_T = TypeVar("_T")


def nest_asyncio_enabled():
    return getenv("SUPERTOKENS_NEST_ASYNCIO", "") == "1"


def create_event_loop() -> (
    tuple[asyncio.AbstractEventLoop, Optional[asyncio.AbstractEventLoopPolicy]]
):
    _cur_event_loop_policy = None

    if nest_asyncio_enabled() and uvloop_available:
        _cur_event_loop_policy = asyncio.get_event_loop_policy()
        asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())

    loop = asyncio.new_event_loop()

    if nest_asyncio_enabled():
        import nest_asyncio  # type: ignore

        nest_asyncio.apply(loop)  # type: ignore

    asyncio.set_event_loop(loop)

    return loop, _cur_event_loop_policy


def get_or_create_event_loop() -> (
    tuple[
        asyncio.AbstractEventLoop,
        Optional[asyncio.AbstractEventLoopPolicy],
        bool
    ]
):
    new_loop = False
    try:
        loop = asyncio.get_event_loop()

        _cur_event_loop_policy = None
        if (
            nest_asyncio_enabled()
            and uvloop_available
            and isinstance(loop, uvloop.Loop)  # type: ignore
            and loop.is_running()
        ):
            loop, _cur_event_loop_policy = create_event_loop()
            new_loop = True

        return loop, _cur_event_loop_policy, new_loop
    except Exception as ex:
        if "There is no current event loop in thread" in str(ex):
            loop, _cur_event_loop_policy = create_event_loop()
            new_loop = True

            return loop, _cur_event_loop_policy, new_loop
        raise ex


def close_loop(
    loop: asyncio.AbstractEventLoop,
    _cur_event_loop_policy: Optional[asyncio.AbstractEventLoopPolicy],
    new_loop: bool
) -> None:
    if new_loop:
        loop.close()

    if _cur_event_loop_policy is not None:
        asyncio.set_event_loop_policy(_cur_event_loop_policy)


def sync(co: Coroutine[Any, Any, _T]) -> _T:
    loop, _cur_event_loop_policy, new_loop = get_or_create_event_loop()

    result = loop.run_until_complete(co)

    close_loop(loop, _cur_event_loop_policy, new_loop)

    return result
