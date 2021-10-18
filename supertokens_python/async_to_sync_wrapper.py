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

import sys
from functools import singledispatch, wraps
import asyncio
import inspect
import types
from typing import Any, Callable, Generator

PY35 = sys.version_info >= (3, 5)


def _is_awaitable(co: Generator[Any, None, Any]) -> bool:
    if PY35:
        return inspect.isawaitable(co)
    else:
        return (isinstance(co, types.GeneratorType) or
                isinstance(co, asyncio.Future))


def check_event_loop():
    try:
        asyncio.get_event_loop()
    except RuntimeError as ex:
        if "There is no current event loop in thread" in str(ex):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)


@singledispatch
def sync(co: Any):
    raise TypeError('Called with unsupported argument: {}'.format(co))


@sync.register(asyncio.Future)
@sync.register(types.GeneratorType)
def sync_co(co: Generator[Any, None, Any]) -> Any:
    if not _is_awaitable(co):
        raise TypeError('Called with unsupported argument: {}'.format(co))
    check_event_loop()
    return asyncio.get_event_loop().run_until_complete(co)


@sync.register(types.FunctionType)
@sync.register(types.MethodType)
def sync_fu(f: Callable[..., Any]) -> Callable[..., Any]:
    if not asyncio.iscoroutinefunction(f):
        raise TypeError('Called with unsupported argument: {}'.format(f))

    @wraps(f)
    def run(*args, **kwargs):
        return asyncio.get_event_loop().run_until_complete(f(*args, **kwargs))

    return run


if PY35:
    sync.register(types.CoroutineType)(sync_co)
