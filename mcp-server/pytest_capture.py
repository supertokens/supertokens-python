"""Pytest plugin that captures per-test stdout/stderr/traceback to JSON files.

This plugin is loaded by the MCP server via ``PYTHONPATH=/opt/mcp-server pytest -p pytest_capture``.
It writes one JSON file per test into the ``test-output/`` directory so the MCP server
can serve detailed per-test results through the ``test_output`` tool.
"""

import hashlib
import json
import os
import time

import pytest

OUTPUT_DIR = os.path.join(os.environ.get("PYTHON_MCP_WORKSPACE", "."), "test-output")


def _safe_filename(test_id: str) -> str:
    """Create a filesystem-safe filename from a test ID."""
    h = hashlib.sha256(test_id.encode()).hexdigest()[:12]
    safe = test_id.replace("/", "_").replace("::", "__").replace(" ", "_")
    # Truncate long names but keep the hash for uniqueness
    if len(safe) > 180:
        safe = safe[:180]
    return f"{safe}_{h}.json"


# Storage keyed by nodeid
_test_data: dict = {}


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Record test start time."""
    _test_data[item.nodeid] = {
        "testId": item.nodeid,
        "className": str(item.fspath)
        if hasattr(item, "fspath")
        else item.nodeid.split("::")[0],
        "testName": item.name,
        "stdout": "",
        "stderr": "",
        "resultType": "SUCCESS",
        "startTime": int(time.time() * 1000),
        "endTime": 0,
        "duration": 0,
        "failureMessage": "",
        "failureTrace": "",
    }


def pytest_runtest_makereport(item, call):
    """Capture output and failure info from each test phase."""
    data = _test_data.get(item.nodeid)
    if data is None:
        return

    # Capture stdout/stderr from the call
    if call.when == "call":
        if hasattr(call, "stdout") and call.stdout:
            data["stdout"] += call.stdout
        if hasattr(call, "stderr") and call.stderr:
            data["stderr"] += call.stderr

    if call.excinfo is not None:
        if call.when in ("call", "setup"):
            data["resultType"] = "FAILURE"
            data["failureMessage"] = str(call.excinfo.value)
            try:
                data["failureTrace"] = str(call.excinfo.getrepr())
            except Exception:
                data["failureTrace"] = str(call.excinfo)


@pytest.hookimpl(trylast=True)
def pytest_runtest_logreport(report):
    """Write per-test JSON after the test completes (on the 'call' or final phase)."""
    data = _test_data.get(report.nodeid)
    if data is None:
        return

    # Accumulate captured output from the report
    if report.capstdout:
        data["stdout"] += report.capstdout
    if report.capstderr:
        data["stderr"] += report.capstderr

    # Capture failure info from the report if not already captured
    if report.failed:
        data["resultType"] = "FAILURE"
        if report.longrepr and not data["failureTrace"]:
            data["failureTrace"] = str(report.longrepr)
            # Extract short message
            if hasattr(report.longrepr, "reprcrash") and report.longrepr.reprcrash:
                data["failureMessage"] = report.longrepr.reprcrash.message
    elif report.skipped:
        data["resultType"] = "SKIPPED"
        if report.longrepr:
            data["failureMessage"] = str(report.longrepr)

    # Only write on the final phase (call or teardown)
    if report.when == "call" or (report.when == "teardown"):
        # On teardown, finalize timing and write
        if report.when == "teardown":
            data["endTime"] = int(time.time() * 1000)
            data["duration"] = data["endTime"] - data["startTime"]
            _write_test_output(data)
        elif report.when == "call" and report.nodeid not in _written:
            # For tests that don't have a teardown report, write on call
            pass  # We'll write on teardown


# Track which tests have been written
_written: set = set()


def _write_test_output(data: dict):
    """Write test output JSON to the output directory."""
    if data["testId"] in _written:
        return
    _written.add(data["testId"])

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = _safe_filename(data["testId"])
    filepath = os.path.join(OUTPUT_DIR, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass  # Don't fail tests due to output capture issues
