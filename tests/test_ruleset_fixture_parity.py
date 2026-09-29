"""Fixture parity with pre-built EventChannel events used for rule testing.

Sources:
- the 62 `{"win":...}` events in Wazuh 4.14.10
  ruleset/testing/tests/{win_event_channel,sysmon,powershell}.ini;
- the 9 events in zbalkan/wazuh-rule-tests tests/test_win_security_rules.py.

Both are pre-built JSON fed through the generic JSON decoder, so they confirm
value formats but not key order or bytes. Each event is checked in two ways:

- value-format invariants shared with the spec (X1, X2, A1, E1, Y2, Y4);
- a round trip: the event is turned back into single-quoted EvtRender-style XML
  (each value X2-unescaped once, the message stubbed as the rendered text) and
  run through wazuhevtx. The decoded fields must equal the fixture's. Derived
  fields (severityValue, category, subcategory, auditPolicyChanges) are not put
  back into the XML, so wazuhevtx must recompute them (Y3, E5, E6).
"""
import json
import pathlib
import re

import pytest
import win32evtlog

from wazuhevtx.evtx2json import EvtxToJson


FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
RULESET_FILES = ("win_event_channel.ini", "sysmon.ini", "powershell.ini")
RULE_TESTS_FILE = "win_security_rules.jsonl"

OUTLIERS = {
    # Hand-authored 4104 events upstream: the message is raw script text without
    # the Y4 quotes, and powershell.ini:2 ends scriptBlockText with a lone "\".
    *{("powershell.ini", line) for line in (2, 8, 14, 20, 50)},
    # 4698 event, identical in upstream ruleset/testing/tests/win_security.ini:32.
    # It is a valid rule test, but it cannot be DecodeWinevt output: the message
    # has no closing quote, which cJSON_PrintUnformatted always adds, and
    # taskContent is cut to "&lt".
    (RULE_TESTS_FILE, "a_scheduled_task_was_created"),
}

DERIVED_SYSTEM = {"severityValue", "message"}
DERIVED_EVENTDATA = {"category", "subcategory", "auditPolicyChanges"}
PROVIDER_ATTRIBUTES = {
    "providerName": "Name",
    "providerGuid": "Guid",
    "eventSourceName": "EventSourceName",
}


def load_fixtures():
    fixtures = []
    for name in RULESET_FILES:
        path = FIXTURE_DIR / "wazuh_ruleset" / name
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"log \d+ pass = (\{.*)$", line)
            if match:
                fixtures.append((name, number, json.loads(match.group(1))))
    path = FIXTURE_DIR / "wazuh_rule_tests" / RULE_TESTS_FILE
    for line in path.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        fixtures.append((RULE_TESTS_FILE, case["id"], json.loads(case["log"])))
    return fixtures


FIXTURES = load_fixtures()
PARITY = [f for f in FIXTURES if (f[0], f[1]) not in OUTLIERS]
IDS = [f"{name}:{number}" for name, number, _ in PARITY]


def xml_derived_values(win):
    for section, fields in win.items():
        for key, value in fields.items():
            if section == "system" and key in DERIVED_SYSTEM:
                continue
            if section == "eventdata" and key in DERIVED_EVENTDATA:
                continue
            yield f"{section}.{key}", value


def x2_unescape(value):
    return json.loads('"' + value + '"')


def upper_first(name):
    return name[:1].upper() + name[1:]


def rebuild_xml(win):
    provider = []
    system = []
    for key, value in win["system"].items():
        if key in DERIVED_SYSTEM:
            continue
        raw = x2_unescape(value)
        if key in PROVIDER_ATTRIBUTES:
            provider.append((PROVIDER_ATTRIBUTES[key], raw))
        elif key == "systemTime":
            system.append(f"<TimeCreated SystemTime='{raw}'/>")
        elif key == "processID":
            system.append(f"<Execution ProcessID='{raw}'/>")
        elif key == "threadID":
            system.append(f"<Execution ThreadID='{raw}'/>")
        else:
            system.append(f"<{upper_first(key)}>{raw}</{upper_first(key)}>")

    # EvtRender writes Name first; the agent looks for "Provider Name=" (A2).
    order = list(PROVIDER_ATTRIBUTES.values())
    provider.sort(key=lambda attribute: order.index(attribute[0]))
    attributes = " ".join(f"{name}='{raw}'" for name, raw in provider)
    xml = "<Event><System>"
    if provider:
        xml += f"<Provider {attributes}/>"
    xml += "".join(system) + "</System>"

    if "eventdata" in win:
        xml += "<EventData>"
        for key, value in win["eventdata"].items():
            if key in DERIVED_EVENTDATA:
                continue
            raw = x2_unescape(value)
            if key == "data":
                xml += f"<Data>{raw}</Data>"
            else:
                if key == "auditPolicyChangesId":
                    key = "auditPolicyChanges"
                xml += f"<Data Name='{upper_first(key)}'>{raw}</Data>"
        xml += "</EventData>"

    for section, fields in win.items():
        if section in ("system", "eventdata"):
            continue
        children = "".join(
            f"<{upper_first(key)}>{x2_unescape(value)}</{upper_first(key)}>"
            for key, value in fields.items()
        )
        xml += f"<UserData><{upper_first(section)}>{children}</{upper_first(section)}></UserData>"

    return xml + "</Event>"


def test_fixture_counts():
    """62 upstream ruleset events plus 9 rule-test events; 6 outliers excluded."""
    ruleset = [f for f in FIXTURES if f[0] in RULESET_FILES]
    assert len(ruleset) == 62
    assert len(FIXTURES) - len(ruleset) == 9
    assert len(PARITY) == 65
    assert {(name, number) for name, number, _ in FIXTURES} >= OUTLIERS


@pytest.mark.parametrize("name, number, fixture", PARITY, ids=IDS)
def test_fixture_value_invariants(name, number, fixture):
    """X1, X2, A1, E1, Y2, Y4 value formats hold for every upstream fixture."""
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


@pytest.mark.parametrize("name, number, fixture", PARITY, ids=IDS)
def test_fixture_round_trip_matches_wazuhevtx(monkeypatch, name, number, fixture):
    """Y1-Y4, E1-E6, O1, X2: rebuilt XML decodes to the fixture's field values."""
    message = fixture["win"]["system"].get("message")
    if message is not None:
        monkeypatch.setattr(win32evtlog, "EvtOpenPublisherMetadata", lambda **kwargs: object())
        monkeypatch.setattr(win32evtlog, "EvtFormatMessage", lambda *args, **kwargs: message[1:-1])

    converter = EvtxToJson()
    converter._path = "x.evtx"
    actual = converter._EvtxToJson__parse_raw_event(rebuild_xml(fixture["win"]))

    # Field values only: fixtures do not preserve DecodeWinevt's key order.
    assert json.loads(actual) == fixture


@pytest.mark.parametrize(
    "name, number",
    sorted(OUTLIERS, key=str),
    ids=[f"{name}:{number}" for name, number in sorted(OUTLIERS, key=str)],
)
def test_excluded_outliers_are_hand_authored(name, number):
    """The excluded events really lack the Y4 quotes, so the exclusion stays honest."""
    fixture = next(f for n, line, f in FIXTURES if (n, line) == (name, number))
    message = fixture["win"]["system"]["message"]
    assert not (message[:1] == message[-1:] == '"')
