# Wazuh ruleset EventChannel fixtures

Unmodified copies of the ruleset test files from Wazuh, used by
`tests/test_ruleset_fixture_parity.py`:

| File | Upstream path |
|---|---|
| `win_event_channel.ini` | `ruleset/testing/tests/win_event_channel.ini` |
| `sysmon.ini` | `ruleset/testing/tests/sysmon.ini` |
| `powershell.ini` | `ruleset/testing/tests/powershell.ini` |

Source: https://github.com/wazuh/wazuh, branch `4.14.10`, commit
`b930ec80b7f65021b7f3ade4af1660ab11997cd9`. Wazuh is licensed under GPLv2, the same
license as this project.

The 62 `{"win":...}` events in these files are pre-built JSON that Wazuh's
`runtests.py` feeds through the generic JSON decoder, not through `DecodeWinevt`.
They show value formats, but not key order or exact bytes, and a few were edited by
hand upstream.
