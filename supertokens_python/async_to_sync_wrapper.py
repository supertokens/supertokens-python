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


@singledispatch
def sync(co: Any):
    raise TypeError('Called with unsupported argument: {}'.format(co))


@sync.register(asyncio.Future)
@sync.register(types.GeneratorType)
def sync_co(co: Generator[Any, None, Any]) -> Any:
    if not _is_awaitable(co):
        raise TypeError('Called with unsupported argument: {}'.format(co))
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