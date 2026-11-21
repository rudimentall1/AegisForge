from shared.solidity_source_analysis import analyze_solidity_sources


def test_builds_function_inventory_and_interprocedural_call_graph():
    source = """
    contract Vault {
        function withdraw() external onlyOwner {
            _send();
        }
        function _send() internal {
            (bool ok,) = payable(msg.sender).call{value: 1 ether}("");
            require(ok);
        }
        function helper() internal {}
    }
    """
    result = analyze_solidity_sources({"src/Vault.sol": source})
    functions = {item["name"]: item for item in result["functions"]}
    assert {"withdraw", "_send", "helper"} <= set(functions)
    assert "_send" in functions["withdraw"]["calls"]
    assert functions["withdraw"]["modifiers"] == ["onlyOwner"]
    assert functions["_send"]["external_calls"] == ["call"]
    assert functions["_send"]["external_call_sites"][0]["line"] == 7
    assert functions["withdraw"]["line"] == 3
    assert result["call_graph"]


def test_reports_inline_authorization_and_state_write_candidates():
    source = """
    contract Vault {
        address owner;
        uint256 total;
        function setOwner(address next) external {
            require(msg.sender == owner, "not owner");
            owner = next;
            total += 1;
        }
    }
    """
    result = analyze_solidity_sources({"Vault.sol": source})
    fn = next(item for item in result["functions"] if item["name"] == "setOwner")
    assert fn["authorization_signals"]
    assert {"owner", "total"} <= set(fn["state_write_candidates"])
    write_lines = {
        item["state_variable"]: item["line"]
        for item in fn["state_write_sites"]
    }
    assert write_lines == {"owner": 7, "total": 8}


def test_ignores_function_like_text_inside_comments_and_strings():
    source = '''
    contract Example {
        // function fake() external { evil(); }
        string constant note = "function ghost() external { selfdestruct(msg.sender); }";
        function real() external { }
    }
    '''
    result = analyze_solidity_sources({"Example.sol": source})
    assert [item["name"] for item in result["functions"]] == ["real"]


def test_records_unresolved_calls_without_claiming_vulnerability():
    source = """
    contract Router {
        function route(address target) external {
            target.delegatecall("");
            unknownHook();
        }
    }
    """
    result = analyze_solidity_sources({"Router.sol": source})
    fn = result["functions"][0]
    assert fn["external_calls"] == ["delegatecall"]
    assert "unknownHook" in fn["unresolved_calls"]
    assert result["analysis_limits"]["vulnerabilities_confirmed"] == 0


def test_rejects_unbalanced_function_body_as_incomplete_analysis():
    source = "contract Broken { function run() external { if (true) {"
    result = analyze_solidity_sources({"Broken.sol": source})
    assert result["analysis_complete"] is False
    assert result["errors"]
    assert result["analysis_limits"]["vulnerabilities_confirmed"] == 0
