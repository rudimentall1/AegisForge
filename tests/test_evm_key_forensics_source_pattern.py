from tools.evm_key_forensics.check_historical_source_pattern import inspect_source, main


SOURCE = r"""
cl_ulong4 Dispatcher::Device::createSeed() {
#ifdef PROFANITY_DEBUG
    cl_ulong4 r;
    r.s[0] = 1;
    r.s[1] = 1;
    r.s[2] = 1;
    r.s[3] = 1;
    return r;
#else
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<cl_ulong> distr;
    cl_ulong4 r;
    r.s[0] = distr(eng);
    r.s[1] = distr(eng);
    r.s[2] = distr(eng);
    r.s[3] = distr(eng);
    return r;
#endif
}
"""


def test_expected_historical_source_pattern_matches():
    result = inspect_source(SOURCE)
    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"
    assert result["errors"] == []
    assert result["historical_code_executed"] is False
    assert result["wallet_material_used"] is False
    assert result["historical_vulnerability_reproduced"] is False
    assert len(result["source_sha256"]) == 64


def test_second_random_device_seed_call_fails_control():
    mutated = SOURCE.replace("eng(rd())", "eng(rd() + rd())")
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "expected_single_random_device_call" in result["errors"]
    assert "expected_single_mt19937_64_initialization_from_rd" in result["errors"]


def test_extra_random_device_call_elsewhere_in_production_branch_fails():
    mutated = SOURCE.replace(
        "std::uniform_int_distribution<cl_ulong> distr;",
        "std::uniform_int_distribution<cl_ulong> distr;\n    auto extra = rd();",
    )
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "expected_single_random_device_call" in result["errors"]


def test_missing_distribution_call_fails_control():
    mutated = SOURCE.replace("r.s[3] = distr(eng);", "r.s[3] = 0;")
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "expected_four_distribution_calls" in result["errors"]
    assert "expected_one_distribution_assignment_for_word_3" in result["errors"]


def test_comment_cannot_fake_missing_distribution_call():
    mutated = SOURCE.replace(
        "r.s[3] = distr(eng);",
        "// r.s[3] = distr(eng);\n    r.s[3] = 0;",
    )
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "expected_four_distribution_calls" in result["errors"]
    assert "expected_one_distribution_assignment_for_word_3" in result["errors"]


def test_comment_cannot_supply_function_marker():
    mutated = "// cl_ulong4 Dispatcher::Device::createSeed() { }\n" + SOURCE
    result = inspect_source(mutated)
    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"


def test_missing_debug_branch_fails_closed():
    mutated = SOURCE.replace("#ifdef PROFANITY_DEBUG", "#if defined(DEBUG)")
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "debug_branch_structure_ambiguous" in result["errors"]


def test_incomplete_debug_fixed_seed_fails_control():
    mutated = SOURCE.replace("r.s[3] = 1;", "r.s[3] = 0;", 1)
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "debug_fixed_seed_word_3_not_recognized" in result["errors"]


def test_unrelated_source_fails_closed():
    result = inspect_source("int main() { return 0; }")
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "createSeed_function_missing" in result["errors"]



def test_braces_in_comments_do_not_truncate_function_body():
    mutated = SOURCE.replace(
        "#endif",
        "#endif\n    // } this brace is not C++ syntax",
    )
    result = inspect_source(mutated)
    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"


def test_braces_in_string_literals_do_not_truncate_function_body():
    mutated = SOURCE.replace(
        "return r;\n#endif",
        'const char *note = "}";\n    return r;\n#endif',
        1,
    )
    result = inspect_source(mutated)
    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"


def test_unbalanced_real_brace_fails_closed_even_with_comment_brace():
    mutated = SOURCE.replace(
        "return r;\n#endif\n}",
        "return r;\n#endif\n// } comment must not balance the function\n",
    )
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "function_body_unbalanced" in result["errors"]



def test_prototype_cannot_borrow_the_next_function_body():
    mutated = "cl_ulong4 Dispatcher::Device::createSeed();\\n" + SOURCE
    result = inspect_source(mutated)
    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"


def test_duplicate_create_seed_definitions_fail_closed():
    mutated = SOURCE + "\\n" + SOURCE
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "createSeed_definition_ambiguous" in result["errors"]


def test_comment_with_function_definition_does_not_create_ambiguity():
    mutated = "/* " + SOURCE + " */\\n" + SOURCE
    result = inspect_source(mutated)
    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"


def test_cli_rejects_matching_pattern_without_exact_pinned_source_blob(tmp_path, capsys):
    source_path = tmp_path / "Dispatcher.cpp"
    source_path.write_text(SOURCE, encoding="utf-8")

    exit_code = main([str(source_path)])
    captured = capsys.readouterr()
    import json
    result = json.loads(captured.out)

    assert exit_code == 2
    assert result["conclusion"] == "INCONCLUSIVE"
    assert result["pinned_source_blob_matches"] is False
    assert "pinned_upstream_blob_mismatch" in result["errors"]


def test_unterminated_block_comment_fails_closed():
    result = inspect_source(SOURCE + chr(10) + "/* unterminated comment")
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "unterminated_block_comment" in result["errors"]


def test_unterminated_string_literal_fails_closed():
    result = inspect_source(SOURCE + chr(10) + 'const char *note = "unterminated;')
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "unterminated_string" in result["errors"]

def test_unescaped_newline_in_string_literal_fails_closed():
    mutated = SOURCE + chr(10) + 'const char *note = "first line' + chr(10) + 'second line";'
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "newline_in_string" in result["errors"]


def test_unescaped_newline_in_character_literal_fails_closed():
    mutated = SOURCE + chr(10) + "char note = '" + chr(10) + "';"
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "newline_in_char" in result["errors"]

def test_cli_rejects_oversized_source_before_decoding(tmp_path, capsys):
    from tools.evm_key_forensics.check_historical_source_pattern import MAX_SOURCE_BYTES

    source_path = tmp_path / "oversized.cpp"
    source_path.write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))

    exit_code = main([str(source_path)])
    import json
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "source_exceeds_size_limit" in result["errors"]


def test_cli_rejects_invalid_utf8_source(tmp_path, capsys):
    source_path = tmp_path / "invalid-utf8.cpp"
    source_path.write_bytes(b"int main() { // " + bytes([0xff]) + b"\\n}")

    exit_code = main([str(source_path)])
    import json
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "source_invalid_utf8" in result["errors"]



def test_revision_registry_has_distinct_immutable_source_pins():
    from tools.evm_key_forensics.check_historical_source_pattern import PINNED_REVISIONS

    pre = PINNED_REVISIONS["pre-disclosure"]
    post = PINNED_REVISIONS["post-disclosure"]
    assert pre["commit"] != post["commit"]
    assert len(pre["commit"]) == len(post["commit"]) == 40
    assert len(pre["git_blob_sha1"]) == len(post["git_blob_sha1"]) == 40
    assert pre["git_blob_sha1"] != post["git_blob_sha1"]


def test_unknown_source_revision_fails_closed():
    import pytest

    with pytest.raises(ValueError, match="unsupported_pinned_revision"):
        inspect_source(SOURCE, revision="master")
