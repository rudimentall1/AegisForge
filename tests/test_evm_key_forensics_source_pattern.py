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
    result = inspect_source(SOURCE + "\\n/* unterminated comment")
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "unterminated_block_comment" in result["errors"]


def test_unterminated_string_literal_fails_closed():
    result = inspect_source(SOURCE + "\\nconst char *note = \\\"unterminated;")
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "unterminated_string" in result["errors"]
