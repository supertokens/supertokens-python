from typing import Union, List, Any, Dict

import pytest
import threading

from supertokens_python.utils import humanize_time, is_version_gte
from supertokens_python.utils import RWMutex

from tests.utils import is_subset


@pytest.mark.parametrize(
    "version,min_minor_version,is_gte",
    [
        (
            "1.12",
            "1.12",
            True,
        ),
        (
            "1.12.0",
            "1.12",
            True,
        ),
        (
            "2.12.0",
            "1.12",
            True,
        ),
        (
            "1.13",
            "1.12",
            True,
        ),
        (
            "1.13.0",
            "1.12",
            True,
        ),
        (
            "0.11.0",
            "1.12",
            False,
        ),
        (
            "1.11.0",
            "1.11",
            True,
        ),
        # python SDK version related
        (
            "0.13.2",
            "0.13.0",
            True,
        ),
        (
            "0.12.5",
            "0.13.0",
            False,
        ),
    ],
)
def test_util_is_version_gte(version: str, min_minor_version: str, is_gte: bool):
    assert is_version_gte(version, min_minor_version) == is_gte


SECOND = 1000
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE


@pytest.mark.parametrize(
    "ms,out",
    [
        (1 * SECOND, "1 second"),
        (59 * SECOND, "59 seconds"),
        (1 * MINUTE, "1 minute"),
        ((1 * MINUTE + 59 * SECOND), "1 minute"),
        (2 * MINUTE, "2 minutes"),
        (1 * HOUR, "1 hour"),
        ((1 * HOUR + 1 * MINUTE), "1 hour"),
        ((1 * HOUR + 6 * MINUTE), "1.1 hours"),
        ((2 * HOUR + 1 * MINUTE), "2 hours"),
        (5 * HOUR, "5 hours"),
    ],
)
def test_humanize_time(ms: int, out: str):
    assert humanize_time(ms) == out


@pytest.mark.parametrize(
    "d1,d2,result",
    [
        ({"a": {"b": [1, 2]}, "c": 1}, {"c": 1}, True),
        ({"a": {"b": [1, 2]}}, {"a": {"b": [1]}}, True),
        ({"a": {"b": [{"c": 2}, 2]}}, {"a": {"b": [{"c": 2}]}}, True),
        ({"a": {"b": [1, 2]}}, {"a": {"b": [3]}}, False),
    ],
)
def test_is_subset(
    d1: Union[Dict[str, Any], List[Any]],
    d2: Union[Dict[str, Any], List[Any]],
    result: bool,
):
    if result is True:
        assert is_subset(d1, d2)
    else:
        assert not is_subset(d1, d2)


class BankAccount:
    def __init__(self):
        self.balance = 0
        self.mutex = RWMutex()

    def deposit(self, amount: int):
        self.mutex.lock()
        self.balance += amount
        self.mutex.unlock()

    def withdraw(self, amount: int):
        self.mutex.lock()
        self.balance -= amount
        self.mutex.unlock()

    def get_balance(self):
        self.mutex.r_lock()
        balance = self.balance
        self.mutex.r_unlock()
        return balance


def test_rw_mutex_writes():
    account = BankAccount()
    threads: List[threading.Thread] = []

    # Create 10 deposit threads
    for _ in range(10):
        t = threading.Thread(target=account.deposit, args=(10,))
        threads.append(t)

    def balance_is_valid():
        balance = account.get_balance()
        assert balance % 5 == 0 and balance >= 0

    # Create 15 balance checking threads
    for _ in range(15):
        t = threading.Thread(target=balance_is_valid)
        threads.append(t)

    # Create 10 withdraw threads
    for _ in range(10):
        t = threading.Thread(target=account.withdraw, args=(5,))
        threads.append(t)

    # Start all threads
    for t in threads:
        t.start()

    # Wait for all threads to finish
    for t in threads:
        t.join()

    # Check account balance
    expected_balance = 10 * 10  # 10 threads depositing 10 each
    expected_balance -= 10 * 5  # 10 threads withdrawing 5 each
    assert account.get_balance() == expected_balance, "Incorrect account balance"
