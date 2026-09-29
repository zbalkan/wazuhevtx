"""Rebuild EvtRender-style XML from a decoded `{"win":...}` event.

Shared by the fixture parity tests. Each value is X2-unescaped once, so running
the XML through wazuhevtx must reproduce it. Element order follows the key order
of the event: Provider and Execution sit where their first field appears, with
the Provider attributes in EvtRender order (Name first, as the agent's
"Provider Name=" lookup requires). Derived fields (severityValue, message,
category, subcategory, auditPolicyChanges) are left out so wazuhevtx has to
recompute them.
"""
import json

import win32evtlog

from wazuhevtx.evtx2json import EvtxToJson


DERIVED_SYSTEM = {"severityValue", "message"}
DERIVED_EVENTDATA = {"category", "subcategory", "auditPolicyChanges"}
PROVIDER_ATTRIBUTES = {
    "providerName": "Name",
    "providerGuid": "Guid",
    "eventSourceName": "EventSourceName",
}
EXECUTION_ATTRIBUTES = {
    "processID": "ProcessID",
    "threadID": "ThreadID",
}


def x2_unescape(value):
    return json.loads('"' + value + '"')


def upper_first(name):
    return name[:1].upper() + name[1:]


def attribute_element(element, fields, attributes):
    ordered = [name for name in attributes.values() if name in fields]
    return f"<{element} " + " ".join(f"{name}='{fields[name]}'" for name in ordered) + "/>"


def rebuild_system(system):
    provider = {PROVIDER_ATTRIBUTES[k]: x2_unescape(v) for k, v in system.items() if k in PROVIDER_ATTRIBUTES}
    execution = {EXECUTION_ATTRIBUTES[k]: x2_unescape(v) for k, v in system.items() if k in EXECUTION_ATTRIBUTES}
    parts = []
    for key, value in system.items():
        if key in DERIVED_SYSTEM:
            continue
        if key in PROVIDER_ATTRIBUTES:
            if provider:
                parts.append(attribute_element("Provider", provider, PROVIDER_ATTRIBUTES))
                provider = {}
        elif key in EXECUTION_ATTRIBUTES:
            if execution:
                parts.append(attribute_element("Execution", execution, EXECUTION_ATTRIBUTES))
                execution = {}
        elif key == "systemTime":
            parts.append(f"<TimeCreated SystemTime='{x2_unescape(value)}'/>")
        else:
            parts.append(f"<{upper_first(key)}>{x2_unescape(value)}</{upper_first(key)}>")
    return "<System>" + "".join(parts) + "</System>"


def rebuild_event_data(event_data):
    parts = []
    for key, value in event_data.items():
        if key in DERIVED_EVENTDATA:
            continue
        raw = x2_unescape(value)
        if key == "data":
            parts.append(f"<Data>{raw}</Data>")
            continue
        if key == "auditPolicyChangesId":
            key = "auditPolicyChanges"
        parts.append(f"<Data Name='{upper_first(key)}'>{raw}</Data>")
    return "<EventData>" + "".join(parts) + "</EventData>"


def rebuild_xml(win):
    xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    xml += rebuild_system(win["system"])
    if "eventdata" in win:
        xml += rebuild_event_data(win["eventdata"])
    for section, fields in win.items():
        if section in ("system", "eventdata"):
            continue
        children = "".join(
            f"<{upper_first(key)}>{x2_unescape(value)}</{upper_first(key)}>"
            for key, value in fields.items()
        )
        xml += f"<UserData><{upper_first(section)}>{children}</{upper_first(section)}></UserData>"
    return xml + "</Event>"


def convert(monkeypatch, win):
    """Run rebuilt XML through wazuhevtx, stubbing the rendered message if any."""
    message = win["system"].get("message")
    if message is not None:
        monkeypatch.setattr(win32evtlog, "EvtOpenPublisherMetadata", lambda **kwargs: object())
        monkeypatch.setattr(win32evtlog, "EvtFormatMessage", lambda *args, **kwargs: message[1:-1])
    converter = EvtxToJson()
    converter._path = "x.evtx"
    return converter._EvtxToJson__parse_raw_event(rebuild_xml(win))
