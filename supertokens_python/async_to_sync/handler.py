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
    """
    Abstract class to handle async-to-sync in various environments.
    """

    async_type: AsyncType
    """The type of async handling to use"""

    create_loop_thread: bool
    """Whether a thread needs to be created to run an event loop"""

    loop: Optional[asyncio.AbstractEventLoop]
    """The event loop to use for async-to-sync conversions"""

    is_loop_threaded: bool
    """Whether the passed loop is running in a thread"""

    def __init__(
        self,
        create_loop_thread: bool,
        loop: Optional[asyncio.AbstractEventLoop],
        is_loop_threaded: bool,
    ):
        # TODO: Add checks on the socket to see if it's patched by Gevent/Eventlet

        # Either the user passes in a loop or tells us to create a thread, not both
        # If neither is passed, we use the default event loop handling
        if loop is not None and create_loop_thread:
            raise ValueError("Pass either `loop` or `create_loop_thread`, not both")

        if is_loop_threaded:
            if loop is None and not create_loop_thread:
                raise ValueError(
                    "Loop cannot be marked as threaded without passing in `loop` or `create_loop_thread`"
                )

        if create_loop_thread:
            is_loop_threaded = True

        self.loop = loop
        self.create_loop_thread = create_loop_thread
        self.is_loop_threaded = is_loop_threaded
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
        # Event loop running in separate thread
        if self.is_loop_threaded:
            if self.loop is None:
                raise ValueError(
                    "Expected `loop` to not be `None` when `is_loop_threaded` is True"
                )

            future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
            return future.result()

        # Normal event loop in the current thread
        if loop is None:
            loop = create_or_get_event_loop()

        return loop.run_until_complete(coroutine)


class DefaultHandler(_AsyncHandler):
    """
    Default async handler for Asyncio-based apps.
    """
    async_type = AsyncType.asyncio

    def __init__(self):
        super().__init__(create_loop_thread=False, loop=None, is_loop_threaded=False)

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        return super()._default_run_as_sync(coroutine, self.loop)


class AsyncioHandler(_AsyncHandler):
    """
    Async handler specific to Asyncio-based apps.

    Only meant for cases where existing event loops need to be re-used, or new
    threaded-loops need to be created.
    For normal use-cases, prefer the `DefaultHandler`.
    """
    async_type = AsyncType.asyncio

    def __init__(
        self,
        create_loop_thread: bool = False,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        is_loop_threaded: bool = False,
    ):
        # NOTE: Creating a non-threaded loop and storing it causes asyncio context issues.
        # Handles missing loops similar to `DefaultHandler`
        if loop is not None and not is_loop_threaded:
            raise ValueError(
                "For existing, non-threaded loops in asyncio, prefer using DefaultHandler"
            )

        super().__init__(
            create_loop_thread=create_loop_thread,
            loop=loop,
            is_loop_threaded=is_loop_threaded,
        )

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        return super()._default_run_as_sync(coroutine, self.loop)


class GeventHandler(_AsyncHandler):
    """
    Async handler specific to Gevent-based apps.

    Does not work optimally with event loops on the same thread, will drop requests.
    Requires a separate thread for the event loop to work well.
    """
    async_type = AsyncType.gevent

    def __init__(
        self,
        create_loop_thread: bool = True,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        is_loop_threaded: bool = True,
    ):
        if not create_loop_thread:
            if not is_loop_threaded:
                raise ValueError(
                    "Non-Threaded gevent loops result in stuck requests, use a threaded loop instead"
                )

        super().__init__(
            create_loop_thread=create_loop_thread,
            loop=loop,
            is_loop_threaded=is_loop_threaded,
        )

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        # When a loop isn't declared or is not in a thread, handle as usual
        if self.loop is None or not self.is_loop_threaded:
            return super()._default_run_as_sync(coroutine, self.loop)

        # When loop is in a thread, we can optimize using Events
        from gevent.event import Event  # type: ignore

        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        event = Event()  # type: ignore
        future.add_done_callback(lambda _: event.set())  # type: ignore
        event.wait()  # type: ignore
        return future.result()


class EventletHandler(_AsyncHandler):
    """
    Async handler specific to Eventlet-based apps.

    Does not work with event loops on the same thread.
    Requires a separate thread for the event loop.
    """
    async_type = AsyncType.eventlet

    def __init__(
        self,
        create_loop_thread: bool = True,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        is_loop_threaded: bool = True,
    ):
        if not create_loop_thread:
            if loop is None or not is_loop_threaded:
                raise ValueError(
                    "Cannot use eventlet with Supertokens without a dedicated event loop thread. "
                    "Please set `create_loop_thread=True` or pass in a threaded event loop."
                )

        super().__init__(
            create_loop_thread=create_loop_thread,
            loop=loop,
            is_loop_threaded=is_loop_threaded,
        )

    def run_as_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        # Eventlet only works well when the event loop is in a different thread
        if self.loop is None or not self.is_loop_threaded:
            raise ValueError(
                "Cannot use eventlet with Supertokens without a dedicated event loop thread. "
                "Please set `create_loop_thread=True` or pass in a threaded event loop."
            )

        # Use Events to handle loop callbacks
        from eventlet.event import Event  # type: ignore

        future = asyncio.run_coroutine_threadsafe(coroutine, loop=self.loop)
        event = Event()  # type: ignore
        future.add_done_callback(lambda _: event.send())  # type: ignore
        event.wait()  # type: ignore
        return future.result()


ConcreteAsyncHandler = Union[
    DefaultHandler, AsyncioHandler, GeventHandler, EventletHandler
]
