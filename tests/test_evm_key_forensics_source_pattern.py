from tools.evm_key_forensics.check_historical_source_pattern import inspect_source


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
