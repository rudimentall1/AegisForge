import hashlib
import json
from urllib.parse import urlparse
import requests
from shared.capability_grant import intent_hash

class HttpOutcomeVerificationError(ValueError):
    pass

class HttpOutcomeVerifier:
    def __init__(self, allowed_hosts=None, timeout=10, session=None):
        self.allowed_hosts = {str(v).strip().lower() for v in (allowed_hosts or []) if str(v).strip()}
        self.timeout = float(timeout)
        self.session = session or requests.Session()
    def _validate_url(self, url):
        parsed = urlparse(str(url))
        if parsed.scheme != "http" or not parsed.hostname:
            raise HttpOutcomeVerificationError("http_verify_url_required")
        if parsed.hostname.lower() not in self.allowed_hosts:
            raise HttpOutcomeVerificationError("http_verify_host_not_allowed")
    def verify(self, intent, receipt):
        payload = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
        if payload.get("status") != "EXECUTED": raise HttpOutcomeVerificationError("receipt_not_executed")
        expected_hash = intent_hash(intent)
        if payload.get("intent_hash") != expected_hash: raise HttpOutcomeVerificationError("receipt_intent_hash_mismatch")
        if payload.get("action") != intent.action: raise HttpOutcomeVerificationError("receipt_action_mismatch")
        params = dict(getattr(intent, "parameters", {}) or {})
        verify_url = params.get("verify_url") or params.get("url") or intent.target
        self._validate_url(verify_url)
        response = self.session.get(verify_url, timeout=self.timeout)
        try: observed = response.json()
        except ValueError: observed = response.text[:4096]
        if params.get("expected_state") is not None and observed != params["expected_state"]:
            raise HttpOutcomeVerificationError("http_expected_state_mismatch")
        checks = ["receipt_status","intent_binding","action_binding","independent_get"]
        canonical = json.dumps({"receipt_id":payload.get("receipt_id"),"intent_hash":expected_hash,"action":intent.action,"target":str(intent.target),"observed":observed,"checks":checks},sort_keys=True,separators=(",",":"))
        return {"outcome_id":hashlib.sha256(canonical.encode()).hexdigest(),"status":"PROVEN","verifier":"http_independent_get_v1","receipt_id":payload.get("receipt_id"),"intent_hash":expected_hash,"action":intent.action,"target":str(intent.target),"observed_state":observed,"checks":checks}
