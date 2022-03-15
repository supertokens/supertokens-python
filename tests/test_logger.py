import json
from unittest import TestCase
from unittest.mock import MagicMock, patch

from supertokens_python.constants import VERSION
from supertokens_python.logger import LoggerCodes, debug_logger, info_logger


class LoggerUtilsTests(TestCase):
    @patch('supertokens_python.logger._get_iso_date', return_value='iso_date')
    def test_debug_logger_func(self, mock_iso_date: MagicMock):
        with self.assertLogs('com.supertokens', level='DEBUG') as captured:
            debug_logger('foo', LoggerCodes.API_RESPONSE)

        assert len(captured.records) == 1
        assert captured.records[0].getMessage() == json.dumps({
            "t": "iso_date",
            "sdkVer": VERSION,
            "message": "API replied with status foo",
            "debugCode": 1
        })

    @patch('supertokens_python.logger._get_iso_date', return_value='iso_date')
    def test_info_logger_func(self, mock_iso_date: MagicMock):
        with self.assertLogs('com.supertokens', level='INFO') as captured:
            info_logger('bar')

        assert len(captured.records) == 1
        assert captured.records[0].getMessage() == json.dumps({
            "t": "iso_date",
            "sdkVer": VERSION,
            "message": "bar",
        })
