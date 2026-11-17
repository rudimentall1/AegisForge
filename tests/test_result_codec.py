from shared.result_codec import decode, encode


def test_result_codec_round_trip_large_json():
    value = {
        "role": "security_checker",
        "findings": [
            {"id": i, "title": "Repeated finding", "evidence": "x" * 400}
            for i in range(20)
        ],
    }

    encoded = encode(value)
    assert isinstance(encoded, (str, bytes))
    assert decode(encoded) == value


def test_result_codec_reads_legacy_json():
    value = {"status": "completed", "value": [1, 2, 3]}
    raw = '{"status":"completed","value":[1,2,3]}'
    assert decode(raw) == value
