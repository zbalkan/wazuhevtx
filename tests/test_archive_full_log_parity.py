"""Byte-level parity with real `full_log` values from a Wazuh 4.14.x manager.

fixtures/archive_full_logs.jsonl holds 130 `full_log` strings produced by the
`windows_eventchannel` decoder (DecodeWinevt) for events from location
`EventChannel`, collected from the maintainer's own environment. Unlike the
ruleset fixtures, these are real decoder output, so they are compared byte for
byte:

- S1/S2: compact, raw-UTF-8 re-serialization reproduces the stored bytes, so
  Python's JSON escaping matches cJSON_PrintUnformatted on this data;
- a round trip through fixture_xml.rebuild_xml and wazuhevtx reproduces the
  exact `full_log`. Key order inside System and EventData comes from the rebuilt
  XML, so this confirms the placement of severityValue and message after the
  System fields (S3) and every value (X2, A1, Y1-Y4, E1).
"""
import json
import pathlib

import pytest

from fixture_xml import convert


FIXTURE_FILE = pathlib.Path(__file__).parent / "fixtures" / "archive_full_logs.jsonl"
RECORDS = [json.loads(line) for line in FIXTURE_FILE.read_text(encoding="utf-8").splitlines()]
IDS = [record["id"] for record in RECORDS]


def test_archive_fixture_source():
    """All records are DecodeWinevt output for EventChannel events."""
    assert len(RECORDS) == 130
    assert {record["decoder"] for record in RECORDS} == {"windows_eventchannel"}
    assert {record["location"] for record in RECORDS} == {"EventChannel"}


@pytest.mark.parametrize("record", RECORDS, ids=IDS)
def test_full_log_serialization_matches_cjson(record):
    """S1/S2: winevtchannel.c:725 cJSON_PrintUnformatted, reproduced by __serialize."""
    full_log = record["full_log"]
    assert json.dumps(json.loads(full_log), ensure_ascii=False, separators=(",", ":")) == full_log


@pytest.mark.parametrize("record", RECORDS, ids=IDS)
def test_full_log_round_trip_is_byte_identical(monkeypatch, record):
    """wazuhevtx reproduces the manager's full_log byte for byte."""
    full_log = record["full_log"]
    assert convert(monkeypatch, json.loads(full_log)["win"]) == full_log
