"""Regression tests for bounded C++ function extraction.

All fixtures are synthetic snippets. These tests never execute Profanity or
handle wallet/key material.
"""
from __future__ import annotations

import pytest

from tools.evm_key_forensics.independent_source_body_review import (
    ReviewError,
    extract_function,
)


SIGNATURE = b"cl_ulong4 Dispatcher::Device::createSeed()"


def source_with(body: bytes) -> bytes:
    return b"prefix\n" + SIGNATURE + b"\n" + body + b"\nsuffix\n"


def test_signature_inside_line_comment_is_ignored():
    source = b"// " + SIGNATURE + b"\nint unrelated() { return 1; }\n"
    with pytest.raises(ReviewError, match="createSeed_signature_not_found"):
        extract_function(source)


def test_signature_inside_block_comment_is_ignored():
    source = b"/* " + SIGNATURE + b" { fake } */\nint unrelated() { return 1; }\n"
    with pytest.raises(ReviewError, match="createSeed_signature_not_found"):
        extract_function(source)


def test_signature_inside_ordinary_string_is_ignored():
    source = b'const char *s = "' + SIGNATURE + b' { fake }";\n'
    with pytest.raises(ReviewError, match="createSeed_signature_not_found"):
        extract_function(source)


def test_braces_inside_comments_and_literals_do_not_end_function_body():
    body = (
        b'{\n'
        b'  // } ignored\n'
        b'  const char *s = "} { \\"";\n'
        b'  /* { nested-looking comment } */\n'
        b'  if (true) { return {}; }\n'
        b'}'
    )
    extracted = extract_function(source_with(body))
    assert extracted == body


def test_braces_and_signature_inside_cpp_raw_string_are_ignored():
    body = (
        b'{\n'
        b'  const char *s = R"tag(' + SIGNATURE + b' { } )tag";\n'
        b'  if (true) { return {}; }\n'
        b'}'
    )
    assert extract_function(source_with(body)) == body


def test_duplicate_real_function_signatures_are_rejected():
    source = (
        SIGNATURE + b" { return {}; }\n"
        + SIGNATURE + b" { return {}; }\n"
    )
    with pytest.raises(ReviewError, match="createSeed_signature_ambiguous"):
        extract_function(source)


def test_missing_opening_brace_is_rejected():
    with pytest.raises(ReviewError, match="createSeed_opening_brace_not_found"):
        extract_function(SIGNATURE + b";\n")


def test_unbalanced_function_body_is_rejected():
    with pytest.raises(ReviewError, match="createSeed_unbalanced_braces"):
        extract_function(SIGNATURE + b" { if (true) { return {}; }\n")


def test_raw_string_without_terminator_is_rejected():
    source = source_with(b'{ const char *s = R"tag(unterminated }')
    with pytest.raises(ReviewError, match="unterminated_raw_string_literal"):
        extract_function(source)
