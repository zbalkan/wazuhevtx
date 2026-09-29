"""Fixture parity with pre-built EventChannel events used for rule testing.

fixtures/rule_test_events.jsonl holds the 71 `{"win":...}` log strings from the
Wazuh 4.14.10 ruleset tests (ruleset/testing/tests/{win_event_channel,
win_security,sysmon,powershell}.ini), extracted unchanged. Each line records its
upstream file:line and test name. The 9 win_security.ini events are identical to
those in zbalkan/wazuh-rule-tests tests/test_win_security_rules.py.

The events are pre-built JSON fed through the generic JSON decoder, so they
confirm value formats but not key order or bytes. Each event is checked in two
ways:

- value-format invariants shared with the spec (X1, X2, A1, E1, Y2, Y4);
- a round trip through fixture_xml.rebuild_xml and wazuhevtx: the decoded
  fields must equal the fixture's, and derived fields must be recomputed
  (Y3, E5, E6).
"""
import json
import pathlib
import re

import pytest

from fixture_xml import DERIVED_EVENTDATA, DERIVED_SYSTEM, convert, x2_unescape


FIXTURE_FILE = pathlib.Path(__file__).parent / "fixtures" / "rule_test_events.jsonl"

OUTLIERS = {
    # Hand-authored 4104 events upstream: the message is raw script text without
    # the Y4 quotes, and powershell.ini:2 ends scriptBlockText with a lone "\".
    *{f"powershell.ini:{line}" for line in (2, 8, 14, 20, 50)},
    # 4698 event: a valid rule test, but it cannot be DecodeWinevt output. The
    # message has no closing quote, which cJSON_PrintUnformatted always adds,
    # and taskContent is cut to "&lt".
    "win_security.ini:32",
}

def load_fixtures():
    fixtures = []
    for line in FIXTURE_FILE.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        fixtures.append((case["source"], json.loads(case["log"])))
    return fixtures


FIXTURES = load_fixtures()
PARITY = [f for f in FIXTURES if f[0] not in OUTLIERS]
IDS = [source for source, _ in PARITY]


def xml_derived_values(win):
    for section, fields in win.items():
        for key, value in fields.items():
            if section == "system" and key in DERIVED_SYSTEM:
                continue
            if section == "eventdata" and key in DERIVED_EVENTDATA:
                continue
            yield f"{section}.{key}", value


def test_fixture_counts():
    """71 ruleset events (62 EventChannel/Sysmon/PowerShell + 9 Security); 6 excluded."""
    assert len(FIXTURES) == 71
    assert sum(source.startswith("win_security.ini:") for source, _ in FIXTURES) == 9
    assert len(PARITY) == 65
    assert {source for source, _ in FIXTURES} >= OUTLIERS


@pytest.mark.parametrize("source, fixture", PARITY, ids=IDS)
def test_fixture_value_invariants(source, fixture):
    """X1, X2, A1, E1, Y2, Y4 value formats hold for every ruleset fixture."""
    win = fixture["win"]
    for field, value in xml_derived_values(win):
        # X2: every XML-derived value is cJSON string content, so each
        # backslash starts a valid escape (C:\Windows -> C:\\Windows).
        x2_unescape(value)
        # A1/X2: no raw CR, LF or other control bytes survive.
        assert not re.search(r"[\x00-\x1f]", value), field
        # X1: entities stay literal; no decoded '<' or bare '&'.
        assert "<" not in value, field
        assert not re.search(
            r"&(?!(amp|lt|gt|quot|apos|#[0-9]+|#x[0-9A-Fa-f]+);)", value), field
        # E1: skipped values never appear.
        assert value not in ("", "-", "(NULL)"), field

    # Y4: the message keeps the quotes cJSON_PrintUnformatted added.
    message = win["system"].get("message")
    if message is not None:
        assert len(message) >= 2 and message[0] == message[-1] == '"'

    # Y2: Correlation and the UserID quirk never produce fields.
    for key in ("correlation", "securityUserID", "userID"):
        assert key not in win["system"]


@pytest.mark.parametrize("source, fixture", PARITY, ids=IDS)
def test_fixture_round_trip_matches_wazuhevtx(monkeypatch, source, fixture):
    """Y1-Y4, E1-E6, O1, X2: rebuilt XML decodes to the fixture's field values."""
    actual = convert(monkeypatch, fixture["win"])

    # Field values only: fixtures do not preserve DecodeWinevt's key order.
    assert json.loads(actual) == fixture


@pytest.mark.parametrize("source", sorted(OUTLIERS))
def test_excluded_outliers_are_hand_authored(source):
    """The excluded events really lack the Y4 quotes, so the exclusion stays honest."""
    fixture = next(f for s, f in FIXTURES if s == source)
    message = fixture["win"]["system"]["message"]
    assert not (message[:1] == message[-1:] == '"')
