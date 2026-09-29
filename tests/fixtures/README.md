# Test fixtures

`archive_full_logs.jsonl` holds 130 real `full_log` values from a Wazuh 4.14.x
manager, collected from the maintainer's own environment (Security, System and
TaskScheduler channels). Every record was decoded by `windows_eventchannel` from
location `EventChannel`, so each `full_log` is genuine DecodeWinevt output. Each
line is `{"id": <alert id>, "decoder": ..., "location": ..., "full_log": ...}`,
with `full_log` stored unchanged. `tests/test_archive_full_log_parity.py` uses
them for byte-level comparison.

`rule_test_events.jsonl` holds the 71 `{"win":...}` log strings from the Wazuh
ruleset tests, extracted unchanged from `ruleset/testing/tests/`:
`win_event_channel.ini` (8), `win_security.ini` (9), `sysmon.ini` (22) and
`powershell.ini` (32). Source: https://github.com/wazuh/wazuh, branch `4.14.10`,
commit `b930ec80b7f65021b7f3ade4af1660ab11997cd9` (GPLv2, the same license as this
project).

Each line is `{"source": "<file>:<line>", "name": "<test section>", "log": "<log>"}`.
The 9 `win_security.ini` events are identical, as parsed JSON, to those in
https://github.com/zbalkan/wazuh-rule-tests `tests/test_win_security_rules.py`,
which were tested against a running Wazuh instance.

The events are pre-built JSON that Wazuh's rule tests feed through the generic
JSON decoder. They show value formats, but not key order or exact bytes, and a few
were edited by hand upstream. `tests/test_ruleset_fixture_parity.py` uses them.
