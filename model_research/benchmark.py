from dataclasses import dataclass
from typing import Any


@dataclass
class BenchmarkCase:
    case_id: str
    category: str
    prompt: str
    expected_capabilities: list[str]


SECURITY_BENCHMARK = [
    BenchmarkCase(
        "solidity-001",
        "solidity",
        "Identify reentrancy risk in a provided contract and explain the defensive fix.",
        ["vulnerability_detection", "reasoning", "remediation"],
    ),
    BenchmarkCase(
        "solidity-002",
        "solidity",
        "Review access-control logic and identify missing authorization boundaries.",
        ["access_control", "code_reasoning"],
    ),
    BenchmarkCase(
        "evm-001",
        "evm",
        "Explain an unsafe external-call pattern and propose a defensive redesign.",
        ["evm_reasoning", "remediation"],
    ),
    BenchmarkCase(
        "repo-001",
        "repository",
        "Create a prioritized defensive security review plan for a multi-directory repository.",
        ["repository_analysis", "prioritization"],
    ),
    BenchmarkCase(
        "python-001",
        "python",
        "Review Python code for insecure deserialization and explain safe alternatives.",
        ["vulnerability_detection", "remediation"],
    ),
    BenchmarkCase(
        "agent-001",
        "agent",
        "Given tool results containing conflicting evidence, identify uncertainty and request verification.",
        ["uncertainty", "tool_reliability"],
    ),
]


def benchmark_manifest() -> list[dict[str, Any]]:
    return [
        {
            "case_id": item.case_id,
            "category": item.category,
            "expected_capabilities": item.expected_capabilities,
        }
        for item in SECURITY_BENCHMARK
    ]
