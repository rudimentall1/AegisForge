from agents.evm_traces import extract_internal_creations


TX_HASH = "0x" + "11" * 32
ADDRESS_A = "0x" + "aa" * 20
ADDRESS_B = "0x" + "bb" * 20
CREATOR = "0x" + "cc" * 20


def test_parity_trace_block_extracts_nested_create_and_create2():
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": [
            {
                "type": "create",
                "transactionHash": TX_HASH,
                "traceAddress": [0],
                "action": {"from": CREATOR, "creationMethod": "create"},
                "result": {"address": ADDRESS_A},
            },
            {
                "type": "create",
                "transactionHash": TX_HASH,
                "traceAddress": [1, 0],
                "action": {"from": ADDRESS_A, "creationMethod": "create2"},
                "result": {"address": ADDRESS_B},
            },
            {
                "type": "create",
                "transactionHash": TX_HASH,
                "traceAddress": [],
                "action": {"from": CREATOR, "creationMethod": "create"},
                "result": {"address": CREATOR},
            },
        ],
    }

    findings = extract_internal_creations(response)

    assert findings == [
        {
            "contract_address": ADDRESS_A,
            "transaction_hash": TX_HASH,
            "deployer": CREATOR,
            "creation_method": "create",
            "trace_address": [0],
        },
        {
            "contract_address": ADDRESS_B,
            "transaction_hash": TX_HASH,
            "deployer": ADDRESS_A,
            "creation_method": "create2",
            "trace_address": [1, 0],
        },
    ]


def test_geth_call_tracer_extracts_recursive_create_and_create2():
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": [
            {
                "txHash": TX_HASH,
                "result": {
                    "type": "CALL",
                    "from": CREATOR,
                    "to": ADDRESS_A,
                    "calls": [
                        {
                            "type": "CREATE",
                            "from": ADDRESS_A,
                            "to": ADDRESS_B,
                            "calls": [],
                        },
                        {
                            "type": "CALL",
                            "from": ADDRESS_A,
                            "to": CREATOR,
                            "calls": [
                                {
                                    "type": "CREATE2",
                                    "from": CREATOR,
                                    "to": ADDRESS_A,
                                    "calls": [],
                                }
                            ],
                        },
                    ],
                },
            }
        ],
    }

    findings = extract_internal_creations(response)

    assert [item["creation_method"] for item in findings] == ["create", "create2"]
    assert [item["contract_address"] for item in findings] == [ADDRESS_B, ADDRESS_A]
    assert [item["trace_address"] for item in findings] == [[0], [1, 0]]


def test_failed_or_malformed_trace_nodes_are_ignored():
    response = {
        "result": [
            {
                "txHash": TX_HASH,
                "result": {
                    "type": "CALL",
                    "calls": [
                        {"type": "CREATE", "from": CREATOR, "to": ADDRESS_A, "error": "revert"},
                        {"type": "CREATE2", "from": CREATOR, "to": "0x123", "calls": []},
                        {"type": "CREATE", "from": CREATOR, "to": ADDRESS_B, "calls": []},
                    ],
                },
            }
        ]
    }

    findings = extract_internal_creations(response)

    assert len(findings) == 1
    assert findings[0]["contract_address"] == ADDRESS_B


def test_rpc_error_and_non_trace_payload_return_empty_list():
    assert extract_internal_creations({"error": {"code": -32601}}) == []
    assert extract_internal_creations({"result": {"not": "a trace list"}}) == []
