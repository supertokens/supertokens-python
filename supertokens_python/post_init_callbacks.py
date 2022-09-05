from typing import Callable, List


class PostSTInitCallbacks:
    """Callbacks that are called after the SuperTokens instance is initialized."""

    callbacks: List[Callable[[], None]] = []

    @staticmethod
    def add_post_init_callback(cb: Callable[[], None]) -> None:
        PostSTInitCallbacks.callbacks.append(cb)

    @staticmethod
    def run_post_init_callbacks() -> None:
        for cb in PostSTInitCallbacks.callbacks:
            cb()

        PostSTInitCallbacks.callbacks = []
