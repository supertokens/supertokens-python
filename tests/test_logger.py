import json
from datetime import datetime as real_datetime
from unittest import TestCase
from unittest.mock import MagicMock, patch

from supertokens_python.constants import VERSION
from supertokens_python.logger import log_debug_message, streamFormatter


class LoggerTests(TestCase):
    @patch("supertokens_python.logger.datetime", wraps=real_datetime)
    def test_json_msg_format(self, datetime_mock: MagicMock):
        datetime_mock.utcnow.return_value = real_datetime(2000, 1, 1)  # type: ignore

        with self.assertLogs(level="DEBUG") as captured:
            log_debug_message("API replied with status 200")

        record = captured.records[0]
        out = json.loads(record.msg)

        assert out == {
            "t": "2000-01-01T00:00Z",
            "sdkVer": VERSION,
            "message": "API replied with status 200",
            "file": "../tests/test_logger.py:16",
        }

    @staticmethod
    def test_stream_formatter_format():
        assert (
            streamFormatter._fmt  # pylint: disable=protected-access
            == "{name} {message}\n"
        )
