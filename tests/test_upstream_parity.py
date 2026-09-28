from test_output_fidelity import parse, parser


def test_upstream_time_created_no_attributes():
    """Port of test_winevt_dec_time_created_no_attributes."""
    assert parse("<Event><System><TimeCreated></TimeCreated></System></Event>") == '{"win":{"system":{}}}'


def test_upstream_execution_no_attributes():
    """Port of test_winevt_dec_execution_no_attributes."""
    assert parse("<Event><System><Execution></Execution></System></Event>") == '{"win":{"system":{}}}'


def test_upstream_execution_one_attribute():
    """Port of test_winevt_dec_execution_one_attribute."""
    assert parse("<Event><System><Execution ProcessID='1'></Execution></System></Event>") == '{"win":{"system":{"processID":"1"}}}'


def test_upstream_provider_no_attributes():
    """Port of test_winevt_dec_provider_no_attributes."""
    assert parse("<Event><System><Provider></Provider></System></Event>") == '{"win":{"system":{}}}'


def test_upstream_provider_unknown_attributes():
    """Port of test_winevt_dec_provider: unknown Provider attributes are ignored."""
    xml = "<Event><System><Provider First='1' Second='2' Third='3'></Provider><Provider Fourth='4'></Provider></System></Event>"
    assert parse(xml) == '{"win":{"system":{}}}'


def test_upstream_join_data_large_accumulation_decoder_cap():
    """Port of join-data accumulation semantics; T1 makes this decoder path unreachable end-to-end."""
    converter, _ = parser()
    joined = ", ".join(["A" * 16000] * 5)
    actual = converter._EvtxToJson__truncate_utf8(joined, 65535)
    assert len(actual.encode()) == 65535
    assert actual == joined[:65535]
