import json

import win32evtlog

from wazuhevtx.evtx2json import EvtxToJson


GUID = "{11111111-1111-1111-1111-111111111111}"
PROVIDER = f"Name='P' Guid='{GUID}'"
KEYWORDS = '<Keywords>0x8020000000000000</Keywords>'


def parser():
    converter = EvtxToJson()
    converter._path = "x.evtx"
    return converter, converter._EvtxToJson__parse_raw_event


def parse(xml):
    return parser()[1](xml)


def event(provider=PROVIDER, level="4", keywords=KEYWORDS, data="", extra="", system_extra=""):
    return (
        f'<Event><System><Provider {provider}/><EventID>4719</EventID>'
        f'<Level>{level}</Level>{keywords}{system_extra}<Channel>Security</Channel>'
        f'</System><EventData>{data}</EventData>{extra}</Event>'
    )


def enable_message(monkeypatch, message):
    monkeypatch.setattr(
        win32evtlog,
        "EvtOpenPublisherMetadata",
        lambda **kwargs: object(),
    )
    monkeypatch.setattr(
        win32evtlog,
        "EvtFormatMessage",
        lambda *args, **kwargs: message,
    )


def test_s1_compact_cjson_print_unformatted_shape():
    """S1: winevtchannel.c:725 uses cJSON_PrintUnformatted."""
    actual = parse(event(data="<Data Name='A'>1</Data><Data Name='B'>2</Data>"))
    expected = (
        '{"win":{"system":{"providerName":"P","providerGuid":"' + GUID +
        '","eventID":"4719","level":"4","keywords":"0x8020000000000000",'
        '"channel":"Security","severityValue":"INFORMATION"},'
        '"eventdata":{"a":"1","b":"2"}}}'
    )
    assert actual == expected
    assert '": "' not in actual


def test_s2_non_ascii_is_raw_utf8():
    """S2: cJSON output keeps UTF-8 characters unescaped."""
    actual = parse(event(data="<Data Name='U'>é</Data>"))
    assert actual.endswith('"eventdata":{"u":"é"}}}')
    assert "\\u00e9" not in actual


def test_s3_construction_order(monkeypatch):
    """S3: winevtchannel.c:168-326,366,627-630,672,689,694-721."""
    enable_message(monkeypatch, "Rendered")
    xml = (
        f"<Event><System><Channel>Security</Channel><Provider Name='P' Guid='{GUID}'/>"
        f"<Keywords>0x8020000000000000</Keywords><EventID>4719</EventID><Level>4</Level>"
        "</System><EventData><Data Name='CategoryId'>%%8274</Data>"
        "<Data>loose</Data><Data Name='SubcategoryId'>%%12800</Data>"
        "<Data Name='AuditPolicyChanges'>%%8451</Data></EventData>"
        "<UserData><First><X>1</X></First></UserData></Event>"
    )
    actual = parse(xml)
    expected = (
        '{"win":{"system":{"channel":"Security","providerName":"P","providerGuid":"' + GUID +
        '","keywords":"0x8020000000000000","eventID":"4719","level":"4",'
        '"severityValue":"INFORMATION","message":"\\\"Rendered\\\""},'
        '"eventdata":{"categoryId":"%%8274","subcategoryId":"%%12800",'
        '"auditPolicyChangesId":"%%8451","category":"Object Access",'
        '"subcategory":"File System","auditPolicyChanges":"Failure added",'
        '"data":"loose"},"first":{"x":"1"}}}'
    )
    assert actual == expected


def test_a1_agent_xml_whitespace_transform_and_message_exemption(monkeypatch):
    """A1: logcollector.c:1140-1163 transforms XML only."""
    enable_message(monkeypatch, "message:\ttab\nnext")
    actual = parse(event(data="<Data Name='S'>line1\r\n\tline2:\tend </Data>"))
    assert '"s":"line1   line2: end"' in actual
    assert '"message":"\\\"message:\\ttab\\nnext\\\""' in actual


def test_a2_message_absent_when_rendering_fails_and_no_name_is_failure():
    """A2: read_win_event_channel.c:482-516 adds Message only on render success."""
    no_metadata = parse(event())
    no_name = parse(event(provider=f"Guid='{GUID}'"))
    assert "message" not in no_metadata
    assert "message" not in no_name
    assert "providerName" not in no_name


def test_x1_oracle_entities_remain_literal():
    """X1 oracle: os_xml.c:413-416,659-660 does not decode XML entities."""
    data = "<Data Name='E'>a &amp;&amp; b &lt;x&gt; &quot;q&quot; &#x41;</Data>"
    actual = parse(event(data=data))
    assert '"e":"a &amp;&amp; b &lt;x&gt; &quot;q&quot; &#x41;"' in actual


def test_x2_oracle_xml_values_keep_one_cjson_escape_layer():
    """X2 oracle: winevtchannel.c:152; os_xml.c:290-294,397."""
    data = (
        "<Data Name='Path'>C:\\Windows\\system32\\</Data>"
        '<Data Name=\'Quote\'>cmd /c "x y"</Data>'
        "<Data Name='Tab'>a\tb</Data>"
        "<Data Name='Ctl'>x\x0fy</Data>"
    )
    actual = parse(event(data=data))
    expected_fragment = (
        r'"eventdata":{"path":"C:\\\\Windows\\\\system32\\\\",'
        r'"quote":"cmd /c \\\"x y\\\"","tab":"a\\tb",'
        r'"ctl":"x\\u000fy"}'
    )
    assert expected_fragment in actual


def test_x3_oracle_20479_bytes_allowed_and_20480_collapses(capsys):
    """X3 oracle: XML_MAXSIZE=20480; 20479 bytes succeeds, 20480 fails."""
    ok = parse(event(data="<Data Name='Blob'>" + ("A" * 20479) + "</Data>"))
    assert ok == (
        '{"win":{"system":{"providerName":"P","providerGuid":"' + GUID +
        '","eventID":"4719","level":"4","keywords":"0x8020000000000000",'
        '"channel":"Security","severityValue":"INFORMATION"},'
        '"eventdata":{"blob":"' + ("A" * 20479) + '"}}}'
    )

    collapsed = parse(event(data="<Data Name='Blob'>" + ("A" * 20480) + "</Data>"))
    assert collapsed == '{"win":{"system":{}}}'
    assert "x.evtx" in capsys.readouterr().err


def test_x4_other_xml_parse_failure_collapses_and_warns(capsys):
    """X4: winevtchannel.c:155-163 keeps a decoded empty system on XML failure."""
    xml = (
        f"<Event><System><Provider Name='P' Guid='{GUID}'/><EventRecordID>42</EventRecordID>"
        "</System><EventData><Data Name='Bad'>broken</EventData></Event>"
    )
    actual = parse(xml)
    assert actual == '{"win":{"system":{}}}'
    err = capsys.readouterr().err
    assert "x.evtx" in err
    assert "record ID 42" in err


def test_x5_oracle_double_quoted_attributes_fail_after_p6(capsys):
    """X5 oracle: JSON-escaped double-quoted XML attributes are not os_xml-parseable."""
    xml = (
        '<Event><System><Provider Name="P"/><EventRecordID>43</EventRecordID>'
        '</System><EventData><Data Name="A">1</Data></EventData></Event>'
    )
    assert parse(xml) == '{"win":{"system":{}}}'
    assert "record ID 43" in capsys.readouterr().err


def test_t1_transport_limit_precedes_x3(capsys):
    """T1/T4: msgs.c:600-607 drops J>65393 before the X3 XML parser limit."""
    def sized_xml(target):
        prefix = "<Event><System><EventRecordID>99</EventRecordID></System><EventData><Data>"
        suffix = "</Data></EventData></Event>"
        base = prefix + suffix
        base_size = len(json.dumps({"Event": base}, ensure_ascii=False, separators=(",", ":")).encode())
        return prefix + ("A" * (target - base_size)) + suffix

    at_limit = sized_xml(65393)
    over_limit = sized_xml(65394)
    assert len(json.dumps({"Event": at_limit}, separators=(",", ":")).encode()) == 65393
    assert len(json.dumps({"Event": over_limit}, separators=(",", ":")).encode()) == 65394

    assert parse(at_limit) == '{"win":{"system":{}}}'
    first_err = capsys.readouterr().err
    assert "failed to parse" in first_err
    assert "dropped" not in first_err

    assert parse(over_limit) is None
    second_err = capsys.readouterr().err
    assert "record ID 99" in second_err
    assert "JSON bytes 65394" in second_err
    assert "dropped" in second_err


def test_t1_suppressed_record_is_not_yielded(monkeypatch, tmp_path):
    """T1: public to_json API remains Generator[str] and skips dropped records."""
    prefix = "<Event><System><EventRecordID>100</EventRecordID></System><EventData><Data>"
    raw = prefix + ("A" * 65400) + "</Data></EventData></Event>"
    calls = iter([[raw], []])
    monkeypatch.setattr(win32evtlog, "EvtQuery", lambda *args: object(), raising=False)
    monkeypatch.setattr(win32evtlog, "EvtNext", lambda *args: next(calls), raising=False)
    converter = EvtxToJson()
    assert list(converter.to_json(tmp_path / "x.evtx")) == []


def test_y1_provider_timecreated_execution_and_no_dict_values():
    """Y1: winevtchannel.c:176-198 emits only defined attributes."""
    xml = (
        f"<Event><System><Provider Name='P' Guid='{GUID}' EventSourceName='Legacy' Other='x'/>"
        "<TimeCreated SystemTime='2026-01-01T00:00:00.000Z' Other='x'/>"
        "<Execution ProcessID='10' ThreadID='20' Other='x'/><EventID>1</EventID>"
        "</System><EventData/></Event>"
    )
    actual = parse(xml)
    expected = (
        '{"win":{"system":{"providerName":"P","providerGuid":"' + GUID +
        '","eventSourceName":"Legacy","systemTime":"2026-01-01T00:00:00.000Z",'
        '"processID":"10","threadID":"20","eventID":"1"}}}'
    )
    assert actual == expected


def test_y2_other_system_fields_empty_rules_and_upstream_quirks():
    """Y2: winevtchannel.c:199-226 lowercases first char and keeps UserID quirks."""
    xml = (
        "<Event><System><Task>7</Task><Computer></Computer><Level></Level><Keywords></Keywords>"
        "<Correlation ActivityID='x'/><Security UserID='S-1-5-18'/><Channel>Security</Channel>"
        "</System><EventData/></Event>"
    )
    actual = parse(xml)
    assert actual == (
        '{"win":{"system":{"task":"7","level":"","keywords":"",'
        '"channel":"Security","severityValue":"UNKNOWN"}}}'
    )
    assert "securityUserID" not in actual
    assert "userID" not in actual
    assert "correlation" not in actual


def test_y3_level_mapping_audit_and_non_numeric():
    """Y3: winevtchannel.c:333-366 maps levels without raising."""
    assert '"severityValue":"CRITICAL"' in parse(event(level="1"))
    assert '"severityValue":"VERBOSE"' in parse(event(level="5"))
    assert '"severityValue":"AUDIT_SUCCESS"' in parse(event(level="0"))
    failure_kw = '<Keywords>0x8010000000000000</Keywords>'
    assert '"severityValue":"AUDIT_FAILURE"' in parse(event(level="0", keywords=failure_kw))
    assert '"severityValue":"UNKNOWN"' in parse(event(level="6"))
    # C strtol() returns 0 for a non-numeric or empty level: the AUDIT branch.
    assert '"severityValue":"AUDIT_SUCCESS"' in parse(event(level="not-a-level"))
    assert '"severityValue":"AUDIT_SUCCESS"' in parse(event(level=""))
    assert '"severityValue":"UNKNOWN"' in parse(event(level="not-a-level", keywords="<Keywords>0x0</Keywords>"))
    assert "severityValue" not in parse(event(level="0", keywords=""))
    # Upstream unit test test_winevt_dec_systemNode_ok: both strtol() and
    # strtoull() yield 0, so level 0 without audit bits falls through to UNKNOWN.
    upstream = parse(event(level="info/warn/error", keywords="<Keywords>keyword1/keyword2</Keywords>"))
    assert '"level":"info/warn/error","keywords":"keyword1/keyword2"' in upstream
    assert '"severityValue":"UNKNOWN"' in upstream


def test_y4_message_keeps_quotes_and_unescapes_once(monkeypatch):
    """Y4: winevtchannel.c:64-86,683-691; string_op.c:952."""
    enable_message(monkeypatch, 'hello\n"world" \\ path')
    actual = parse(event())
    assert '"message":"\\\"hello\\n\\\"world\\\" \\\\ path\\\""' in actual


def test_e1_named_data_single_value_skip_trim_and_no_hex_rewrite():
    """E1: winevtchannel.c:228-262 handles a single named Data like any other."""
    single = parse(event(data="<Data Name='A'>1 </Data>"))
    assert '"eventdata":{"a":"1"}' in single

    actual = parse(event(data=(
        "<Data Name='N'>(NULL)</Data><Data Name='D'>-</Data>"
        "<Data Name='H'>0x0003E7</Data>"
    )))
    assert '"eventdata":{"h":"0x0003E7"}' in actual


def test_e2_unnamed_data_is_joined_string_and_cap_helper():
    """E2: winevtchannel.c:273-286,698-700 joins Data; OS_MAXSTR caps at 65535 bytes."""
    converter, _ = parser()
    actual = parse(event(data="<Data>one</Data><Data>-</Data><Data>two </Data>"))
    assert '"eventdata":{"data":"one, two"}' in actual
    truncated = converter._EvtxToJson__truncate_utf8("A" * 70000, 65535)
    assert len(truncated.encode()) == 65535


def test_e3_non_name_data_attribute_uses_attribute_value_as_key():
    """E3: winevtchannel.c:264-270 uses a non-Name attribute's value as key."""
    actual = parse(event(data="<Data Qualifier='FieldKey'>value</Data>"))
    assert '"eventdata":{"fieldKey":"value"}' in actual


def test_e4_non_data_eventdata_child_is_raw_content():
    """E4: winevtchannel.c:287-290 copies Binary without decoding."""
    actual = parse(event(data="<Binary>414243 </Binary>"))
    assert '"eventdata":{"binary":"414243"}' in actual


def test_e5_audit_policy_id_and_decoding():
    """E5: winevtchannel.c:251-256,640-677 retains ID and decodes known values."""
    actual = parse(event(data="<Data Name='AuditPolicyChanges'>%%8449, %%9999, %%8451</Data>"))
    assert (
        '"eventdata":{"auditPolicyChangesId":"%%8449, %%9999, %%8451",'
        '"auditPolicyChanges":"Success added, Failure added"}' in actual
    )


def test_e6_category_subcategory_mapping_and_gate():
    """E6: winevtchannel.c:333,370-637 maps known IDs only under level+keywords gate."""
    data = "<Data Name='CategoryId'>%%8274</Data><Data Name='SubcategoryId'>%%12800</Data>"
    actual = parse(event(level="0", data=data))
    assert (
        '"eventdata":{"categoryId":"%%8274","subcategoryId":"%%12800",'
        '"category":"Object Access","subcategory":"File System"}' in actual
    )
    gated = parse(event(level="0", keywords="", data=data))
    assert '"category":"Object Access"' not in gated
    unknown = parse(event(data="<Data Name='CategoryId'>%%9999</Data><Data Name='SubcategoryId'>%%1</Data>"))
    assert '"category":' not in unknown


def test_e7_empty_eventdata_is_omitted():
    """E7: winevtchannel.c:697-715 deletes empty eventdata."""
    actual = parse(event(data="<Data Name='N'>(NULL)</Data>"))
    assert "eventdata" not in actual


def test_o1_userdata_merges_grandchildren_under_last_child_name():
    """O1: winevtchannel.c:294-321,716-718 merges into the last child object."""
    extra = (
        "<UserData><First><A>1</A><Skip>-</Skip></First>"
        "<Last><B>2 </B><Null>(NULL)</Null></Last></UserData>"
    )
    actual = parse(event(extra=extra))
    assert actual.endswith('"last":{"a":"1","b":"2"}}}')


def test_x2_applies_to_system_attributes_and_userdata_too():
    """X2 applies to every XML-derived System/EventData/O1 value."""
    xml = (
        "<Event><System><Provider Name='P\\Svc'/><Computer>C:\\Host\\</Computer></System>"
        "<UserData><Payload><Path>C:\\Temp\\</Path></Payload></UserData></Event>"
    )
    actual = parse(xml)
    assert r'"providerName":"P\\\\Svc"' in actual
    assert r'"computer":"C:\\\\Host\\\\"' in actual
    assert r'"payload":{"path":"C:\\\\Temp\\\\"}' in actual


def test_s3_eventdata_children_keep_xml_order_when_tags_repeat():
    """S3: winevtchannel.c:227-293 appends EventData fields in XML child order."""
    data = "<Data Name='A'>1</Data><Binary>ff</Binary><Data Name='B'>2</Data>"
    actual = parse(event(data=data))
    assert '"eventdata":{"a":"1","binary":"ff","b":"2"}' in actual


def test_x1_oracle_attribute_entities_remain_literal():
    """X1 oracle: os_xml.c:659-660 preserves entity text in attribute values."""
    actual = parse("<Event><System><Provider Name='P&amp;Q'/></System></Event>")
    assert actual == '{"win":{"system":{"providerName":"P&amp;Q"}}}'


def test_x3_oracle_attribute_value_20480_bytes_collapses(capsys):
    """X3 oracle: the 20,480-byte os_xml limit applies to attributes as well as content."""
    ok = parse("<Event><System><Provider Name='" + ("A" * 20479) + "'/></System></Event>")
    assert ok is not None and '"providerName":"' + ("A" * 20479) + '"' in ok
    failed = parse("<Event><System><Provider Name='" + ("A" * 20480) + "'/></System></Event>")
    assert failed == '{"win":{"system":{}}}'
    assert "failed to parse" in capsys.readouterr().err


def test_t1_counts_rendered_message_in_agent_json(monkeypatch, capsys):
    """T1: read_win_event_channel.c:509-526 includes Message in J when rendering succeeds."""
    enable_message(monkeypatch, "M" * 65400)
    assert parse(event(data="<Data Name='A'>1</Data>")) is None
    err = capsys.readouterr().err
    assert "dropped" in err
    assert "JSON bytes" in err


def test_y1_timecreated_requires_systemtime_as_first_attribute():
    """Y1: winevtchannel.c:188-192 checks only TimeCreated's first attribute."""
    xml = (
        "<Event><System><TimeCreated Other='x' SystemTime='2026-01-01T00:00:00.000Z'/>"
        "</System></Event>"
    )
    assert parse(xml) == '{"win":{"system":{}}}'


def test_x4_parse_failure_keeps_rendered_message_only(monkeypatch, capsys):
    """X4/Y4: winevtchannel.c:155-163,683-729 keeps Message after XML failure."""
    enable_message(monkeypatch, "Rendered")
    xml = (
        f"<Event><System><Provider Name='P' Guid='{GUID}'/><EventRecordID>44</EventRecordID>"
        "</System><EventData><Data>broken</EventData></Event>"
    )
    assert parse(xml) == '{"win":{"system":{"message":"\\\"Rendered\\\""}}}'
    assert "record ID 44" in capsys.readouterr().err


def test_y4_message_keeps_crlf_and_surrounding_whitespace(monkeypatch):
    """Y4/A2: EvtFormatMessageEvent text reaches analysisd verbatim; the trim is
    a no-op because the quoted message ends with '"'."""
    enable_message(monkeypatch, "  An account was logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n")
    actual = parse(event())
    assert (
        '"message":"\\"  An account was logged on.\\r\\n\\r\\nSubject:\\r\\n'
        '\\tSecurity ID:\\t\\tS-1-5-18\\r\\n\\""' in actual
    )


def test_a2_empty_rendered_message_is_empty_not_none(monkeypatch):
    """A2: an empty rendered message is still added as Message."""
    enable_message(monkeypatch, "")
    assert '"message":"\\"\\""' in parse(event())


def test_a2_publisher_metadata_is_read_from_local_registry(monkeypatch):
    """A2: get_message() calls EvtOpenPublisherMetadata without a log file path."""
    seen = {}

    def metadata(**kwargs):
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(win32evtlog, "EvtOpenPublisherMetadata", metadata)
    monkeypatch.setattr(win32evtlog, "EvtFormatMessage", lambda *args, **kwargs: "m")
    parse(event())
    assert seen["PublisherIdentity"] == "P"
    assert seen["LogFilePath"] is None


def test_e5_audit_policy_decoding_is_not_gated_on_level_keywords():
    """E5: in 4.14.10 the auditPolicyChanges block sits outside if(level && keywords)."""
    data = "<Data Name='AuditPolicyChanges'>%%8449</Data>"
    actual = parse(event(keywords="", data=data))
    assert (
        '"eventdata":{"auditPolicyChangesId":"%%8449",'
        '"auditPolicyChanges":"Success added"}' in actual
    )


def test_e1_e2_whitespace_only_values_keep_first_character():
    """E1/E2/O1: replace_win_format() never trims the first character."""
    actual = parse(event(
        data="<Data Name='A'>  </Data><Data>\t </Data><Binary> \t</Binary>",
        extra="<UserData><U><V>  </V></U></UserData>",
    ))
    # Under X2 a TAB is the two characters "\\t" when trimmed, so it survives.
    assert '"eventdata":{"a":" ","binary":" \\\\t","data":"\\\\t"}' in actual
    assert '"u":{"v":" "}' in actual


def test_y2_empty_channel_is_emitted():
    """Y2: winevtchannel.c adds channel without an emptiness check."""
    actual = parse("<Event><System><Channel></Channel><EventID>1</EventID></System></Event>")
    assert actual == '{"win":{"system":{"channel":"","eventID":"1"}}}'


def test_lone_surrogates_become_replacement_character(monkeypatch):
    """convert_windows_string() replaces unpaired UTF-16 surrogates with U+FFFD."""
    enable_message(monkeypatch, "m\udc00")
    actual = parse(event(data="<Data Name='S'>a\ud800b</Data>"))
    assert '"s":"a\ufffdb"' in actual
    assert '"message":"\\"m\ufffd\\""' in actual
    actual.encode("utf-8")
