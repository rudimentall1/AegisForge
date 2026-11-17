import json

class OutcomeContractError(ValueError): pass

CONTRACT_REQUIRED_ACTIONS={"delete","publish","api_request","mcp_tool_call","transfer","release"}
CONTRACT_TYPES={
 "state_match":{"required":{"type","verifier","expected_state"},"allowed":{"type","verifier","expected_state"},"verifiers":{"filesystem_independent_v1"},"actions":{"delete"}},
 "artifact_exists":{"required":{"type","verifier","path","expected_exists"},"allowed":{"type","verifier","path","expected_exists"},"verifiers":{"artifact_independent_v1"},"actions":{"publish"}},
 "http_state":{"required":{"type","verifier","verify_url","expected_state"},"allowed":{"type","verifier","verify_url","expected_state"},"verifiers":{"http_independent_get_v1"},"actions":{"api_request"}},
 "mcp_state":{"required":{"type","verifier","endpoint","tool","arguments","read_only","expected_state"},"allowed":{"type","verifier","endpoint","tool","arguments","read_only","expected_state","headers","request_id"},"verifiers":{"mcp_independent_read_v1"},"actions":{"mcp_tool_call"}},
 "transaction_confirmed":{"required":{"type","verifier","transaction_id"},"allowed":{"type","verifier","transaction_id","expected_status"},"verifiers":{"transaction_independent_v1"},"actions":{"transfer","release"}},
}

def validate_outcome_contract(contract,action=None):
 if contract is None: contract={}
 if not isinstance(contract,dict): raise OutcomeContractError("invalid_outcome_contract")
 value=json.loads(json.dumps(contract,sort_keys=True))
 if not value:
  if action in CONTRACT_REQUIRED_ACTIONS: raise OutcomeContractError("outcome_contract_required")
  return value
 typ=value.get("type")
 if typ not in CONTRACT_TYPES: raise OutcomeContractError("unknown_outcome_contract_type")
 spec=CONTRACT_TYPES[typ]; missing=sorted(spec["required"]-set(value)); extra=sorted(set(value)-spec["allowed"])
 if missing: raise OutcomeContractError("outcome_contract_fields_missing:"+",".join(missing))
 if extra: raise OutcomeContractError("outcome_contract_fields_unknown:"+",".join(extra))
 if not isinstance(value.get("verifier"),str) or not value["verifier"].strip(): raise OutcomeContractError("outcome_contract_verifier_required")
 if value["verifier"] not in spec["verifiers"]: raise OutcomeContractError("outcome_contract_verifier_mismatch")
 if action is not None and action not in spec["actions"]: raise OutcomeContractError("outcome_contract_action_mismatch")
 if typ=="artifact_exists" and (not isinstance(value["path"],str) or not value["path"].strip() or not isinstance(value["expected_exists"],bool)): raise OutcomeContractError("outcome_contract_artifact_invalid")
 if typ=="http_state" and (not isinstance(value["verify_url"],str) or not value["verify_url"].strip()): raise OutcomeContractError("outcome_contract_verify_url_required")
 if typ=="mcp_state":
  if not isinstance(value["endpoint"],str) or not value["endpoint"].strip() or not isinstance(value["tool"],str) or not value["tool"].strip(): raise OutcomeContractError("outcome_contract_mcp_target_required")
  if not isinstance(value["arguments"],dict) or value["read_only"] is not True: raise OutcomeContractError("outcome_contract_mcp_arguments_invalid")
  if "headers" in value and not isinstance(value["headers"],dict): raise OutcomeContractError("outcome_contract_headers_invalid")
  if "request_id" in value and not isinstance(value["request_id"],str): raise OutcomeContractError("outcome_contract_request_id_invalid")
 if typ=="transaction_confirmed" and (not isinstance(value["transaction_id"],str) or not value["transaction_id"].strip()): raise OutcomeContractError("outcome_contract_transaction_id_required")
 return value
