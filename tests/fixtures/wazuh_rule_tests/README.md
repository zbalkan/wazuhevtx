# wazuh-rule-tests EventChannel fixtures

`win_security_rules.jsonl` holds the 9 Windows Security events from
`tests/test_win_security_rules.py` in https://github.com/zbalkan/wazuh-rule-tests,
branch `main`, commit `c1de5e3fe4bce9c99354b70f8fa8998b3bf29167` (GPLv2, the same
license as this project). They are used by `tests/test_ruleset_fixture_parity.py`.

The events are converted from Wazuh's `ruleset/testing/tests/win_security.ini`
(branch `4.14.10`) and are identical to its 9 events as parsed JSON. They were
tested against a running Wazuh instance with the generic JSON decoder.

Each line is `{"id": <pytest.param id>, "log": <log string>}`. The log strings
were extracted with `ast` from the raw-string literals, unchanged. The original
file is not copied because pytest would collect it and it imports `wazuhtester`.
