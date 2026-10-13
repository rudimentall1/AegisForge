"""Contract checks for the fail-closed source provenance schema."""

import json
from pathlib import Path


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "evm_key_forensics"
    / "source-provenance.schema.json"
)


def test_source_provenance_schema_keeps_integrity_and_independence_separate():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == "evm-source-provenance-v1"
    required = set(schema["required"])
    assert {
        "content_integrity",
        "publisher_identity",
        "origin_relationship",
        "independence_assessment",
    } <= required

    independence = schema["properties"]["independence_assessment"]["properties"]
    assert "NOT_ESTABLISHED" in independence["status"]["enum"]
    assert "UNKNOWN" in independence["status"]["enum"]
    assert "CONTENT_HASH_ONLY" in independence["basis"]["enum"]
    assert "URL_ONLY" in independence["basis"]["enum"]
    assert "NO_VERIFIED_PROVENANCE" in independence["basis"]["enum"]


def test_source_provenance_schema_warns_that_shape_is_not_authenticity():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    description = schema["description"].lower()

    assert "shape only" in description
    assert "does not authenticate publishers" in description
    assert "does not" in description and "independent evidence" in description

    publisher = schema["properties"]["publisher_identity"]["properties"]
    assert "UNVERIFIED" in publisher["verification_status"]["enum"]
    assert "UNKNOWN" in publisher["verification_status"]["enum"]


def test_synthetic_unknown_provenance_example_does_not_infer_independence():
    example_path = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "evm_key_forensics"
        / "examples"
        / "source-provenance-unknown.json"
    )
    example = json.loads(example_path.read_text(encoding="utf-8"))

    assert example["content_integrity"]["status"] == "MATCHED"
    assert example["publisher_identity"]["verification_status"] == "UNKNOWN"
    assert example["origin_relationship"]["status"] == "UNKNOWN"
    assert example["independence_assessment"]["status"] == "NOT_ESTABLISHED"
    assert example["independence_assessment"]["basis"] == "NO_VERIFIED_PROVENANCE"
    assert any("does not authenticate" in item for item in example["limitations"])
