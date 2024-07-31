from typing import Callable


class Info:
    core_call_count = 0


def get_func(eval_str: str) -> Callable:  # type: ignore
    if eval_str.startswith("supertokens.init.supertokens.networkInterceptor"):

        def func(*args):  # type: ignore
            Info.core_call_count += 1
            return args  # type: ignore

        return func  # type: ignore

    raise Exception("Unknown eval string")
