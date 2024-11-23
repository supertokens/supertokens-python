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

from abc import ABC, abstractmethod
import asyncio
from enum import Enum
from threading import Thread
from typing import Any, Coroutine, Optional, TypeVar, Union
from supertokens_python.async_to_sync.utils import create_or_get_event_loop

_T = TypeVar("_T")


class AsyncType(Enum):
    asyncio = "asyncio"
    gevent = "gevent"
    eventlet = "eventlet"


class _AsyncHandler(ABC):
    async_type: AsyncType
    create_loop_thread: bool
    loop: Optional[asyncio.AbstractEventLoop]

    def __init__(
        self,
        create_loop_thread: bool,
        loop: Optional[asyncio.AbstractEventLoop],
    ):
        # TODO: Add checks on the socket to see if it's patched by Gevent/Eventlet
        # TODO: Consider setting the type of loop (thread/normal) and base sync implementation on that

        if loop is not None:
            if create_loop_thread:
                raise ValueError("Pass either `loop` or `create_loop_thread`, not both")

        self.loop = loop
        self.create_loop_thread = create_loop_thread
        self._create_loop_thread()
        self._register_loop()

    def _create_loop_thread(self):
        if self.create_loop_thread:
            self.loop = asyncio.new_event_loop()
            loop_thread = Thread(target=self.loop.run_forever, daemon=True)
            loop_thread.start()

    def _register_loop(self):
        import nest_asyncio  # type: ignore

        if self.loop is None:
            nest_asyncio.apply()  # type: ignore
        else:
            # Need to set the event loop before `nest_asyncio.apply`
            asyncio.set_event_loop(loop=self.loop)
            nest_asyncio.apply(loop=self.loop)  # type: ignore

    @abstractmethod
    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        pass

    def _default_run_as_sync(
        self,
        coroutine: Coroutine[Any, Any, _T],
        loop: Optional[asyncio.AbstractEventLoop],
    ) -> _T:
        if loop is None:
            loop = create_or_get_event_loop()

        return loop.run_until_complete(coroutine)


class DefaultHandler(_AsyncHandler):
    async_type = AsyncType.asyncio

    def __init__(self):
        super().__init__(create_loop_thread=False, loop=None)

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        return super()._default_run_as_sync(coroutine, self.loop)


class AsyncioHandler(_AsyncHandler):
    async_type = AsyncType.asyncio

    def __init__(
        self,
        create_loop_thread: bool = False,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        # NOTE: Creating a non-threaded loop and storing it causes asyncio context issues.
        # Handles missing loops similar to `DefaultHandler`
        super().__init__(create_loop_thread=create_loop_thread, loop=loop)

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        if self.loop is None:
            return super()._default_run_as_sync(coroutine, self.loop)

        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        return future.result()


class GeventHandler(_AsyncHandler):
    async_type = AsyncType.gevent

    def __init__(
        self,
        create_loop_thread: bool = True,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        super().__init__(create_loop_thread=create_loop_thread, loop=loop)

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        if self.loop is None:
            return super()._default_run_as_sync(coroutine, self.loop)

        from gevent.event import Event  # type: ignore

        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        event = Event()  # type: ignore
        future.add_done_callback(lambda _: event.set())  # type: ignore
        event.wait()  # type: ignore
        return future.result()


class EventletHandler(_AsyncHandler):
    async_type = AsyncType.eventlet

    def __init__(
        self,
        create_loop_thread: bool = True,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        if not create_loop_thread:
            raise ValueError(
                "Cannot use eventlet with Supertokens without a dedicated event loop thread. "
                "Please set `create_loop_thread=True`."
            )

        super().__init__(create_loop_thread=create_loop_thread, loop=loop)

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        if self.loop is None:
            raise ValueError(
                "Cannot use eventlet with Supertokens without a dedicated event loop thread. "
                "Please set `create_loop_thread=True`."
            )

        from eventlet.event import Event  # type: ignore

        future = asyncio.run_coroutine_threadsafe(coroutine, loop=self.loop)
        event = Event()  # type: ignore
        future.add_done_callback(lambda _: event.send())  # type: ignore
        event.wait()  # type: ignore
        return future.result()


ConcreteAsyncHandler = Union[
    DefaultHandler, AsyncioHandler, GeventHandler, EventletHandler
]
