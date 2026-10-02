import base64
import json
import os
import shutil
import textwrap

from shared.outcome_proof import OutcomeProofError, read_outcome_proof, verify_outcome_proof

BUNDLE_SCHEMA = "aegisforge-proof-bundle-v1"
VERIFIER_NAME = "verify_bundle.py"
README_NAME = "README.md"
PROOF_NAME = "outcome-proof.json"
MANIFEST_NAME = "evidence-manifest.json"
PUBLIC_KEY_NAME = "public-key.txt"
ATTESTATION_NAME = "attestation.json"
REGISTRY_NAME = "attestor-registry.json"

STANDALONE_VERIFIER = r'''#!/usr/bin/env python3
import base64, hashlib, json, os, sys
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception as exc:
    print(f"INVALID: cryptography dependency unavailable: {exc}")
    raise SystemExit(2)

SCHEMA_VERSION = "outcome-proof-v1"
ALGORITHM = "Ed25519"

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def b64(v, field):
    try: return base64.urlsafe_b64decode(str(v).encode("ascii"))
    except Exception as exc: raise ValueError(f"invalid_base64:{field}") from exc

def digest(v):
    return hashlib.sha256(canonical(v).encode("utf-8")).hexdigest()

def manifest_verify(m):
    if not isinstance(m, dict) or m.get("schema_version") != "evidence-manifest-v1": raise ValueError("invalid_manifest_schema")
    entries = m.get("entries")
    if not isinstance(entries, list) or m.get("entry_count") != len(entries): raise ValueError("manifest_entry_count_mismatch")
    leaves=[]
    for e in entries:
        if not isinstance(e, dict) or not all(k in e for k in ("id","type","digest")): raise ValueError("invalid_manifest_entry")
        if not isinstance(e["digest"], str) or len(e["digest"]) != 64: raise ValueError("invalid_manifest_digest")
        leaves.append(hashlib.sha256((str(e["id"])+"\0"+str(e["type"])+"\0"+e["digest"]).encode()).hexdigest())
    # Keep canonical entry order; leaf hashes are not independently sorted.
    if not leaves: root=hashlib.sha256(b"").hexdigest()
    else:
        while len(leaves)>1:
            if len(leaves)%2: leaves.append(leaves[-1])
            leaves=[hashlib.sha256((leaves[i]+leaves[i+1]).encode()).hexdigest() for i in range(0,len(leaves),2)]
        root=leaves[0]
    if m.get("merkle_root") != root: raise ValueError("manifest_merkle_root_mismatch")

def artifact_bindings(p):
    entries={(e["id"],e["type"]):e for e in p["evidence_manifest"]["entries"]}
    required=(("grant","capability_grant"),("receipt","execution_receipt"),("contract","outcome_contract"),("outcome","verified_outcome"),("evidence","outcome_evidence"))
    artifacts={"grant":p["grant"],"receipt":p["receipt"],"contract":p["outcome_contract"],"outcome":p["outcome"],"evidence":p["evidence"]}
    for artifact_id, artifact_type in required:
        entry=entries.get((artifact_id,artifact_type))
        if entry is None: raise ValueError(f"manifest_entry_missing:{artifact_id}")
        if digest(artifacts[artifact_id]) != entry["digest"]: raise ValueError(f"manifest_artifact_mismatch:{artifact_id}")

def integrity(p):
    return {k:p[k] for k in ("schema_version","algorithm","key_id","public_key","grant","receipt","outcome_contract","outcome","evidence","evidence_manifest")}

def signature_payload(p):
    x=integrity(p); x["proof_id"]=p["proof_id"]; return x

def verify(p):
    required=("schema_version","algorithm","key_id","public_key","proof_id","grant","receipt","outcome_contract","outcome","evidence","evidence_manifest","signature")
    for k in required:
        if k not in p: raise ValueError(f"proof_field_missing:{k}")
    if p["schema_version"] != SCHEMA_VERSION or p["algorithm"] != ALGORITHM: raise ValueError("unsupported_proof_schema_or_algorithm")
    if p["outcome"].get("status") != "PROVEN": raise ValueError("proof_outcome_not_proven")
    if p["outcome"].get("verifier") != p["outcome_contract"].get("verifier"): raise ValueError("proof_verifier_mismatch")
    manifest_verify(p["evidence_manifest"])
    if p["proof_id"] != hashlib.sha256(canonical(integrity(p)).encode()).hexdigest(): raise ValueError("proof_id_mismatch")
    pub=b64(p["public_key"],"public_key")
    if len(pub)!=32: raise ValueError("invalid_ed25519_public_key")
    sig=b64(p["signature"],"signature")
    if len(sig)!=64: raise ValueError("invalid_ed25519_signature")
    key=Ed25519PublicKey.from_public_bytes(pub)
    try: key.verify(sig, canonical(signature_payload(p)).encode())
    except Exception as exc: raise ValueError("proof_signature_invalid") from exc
    artifact_bindings(p)
    g=p["grant"]
    if g.get("algorithm") != ALGORITHM or g.get("key_id") != p["key_id"]: raise ValueError("grant_signer_mismatch")
    gs=b64(g.get("signature",""),"grant_signature")
    gp={"algorithm":g["algorithm"],"key_id":g["key_id"],"grant":g.get("grant"),"agent_identity":g.get("agent_identity")}
    try: key.verify(gs, canonical(gp).encode())
    except Exception as exc: raise ValueError("grant_signature_invalid") from exc
    body=g["grant"]; receipt=p["receipt"]
    if body.get("grant_id") != receipt.get("grant_id"): raise ValueError("grant_receipt_binding_mismatch")
    if body.get("task_id") != receipt.get("task_id"): raise ValueError("grant_receipt_task_mismatch")
    if receipt.get("intent_hash") and body.get("intent_hash") != receipt.get("intent_hash"): raise ValueError("grant_receipt_intent_mismatch")
    for field, error in (("agent_id","grant_receipt_agent_mismatch"),("authority_epoch","grant_receipt_epoch_mismatch"),("authority_state","grant_receipt_authority_state_mismatch"),("policy_version","grant_receipt_policy_mismatch")):
        if receipt.get(field) != body.get(field): raise ValueError(error)
    if body.get("outcome_contract") != p["outcome_contract"]: raise ValueError("grant_contract_mismatch")
    agent_id=body.get("agent_id")
    if not agent_id or receipt.get("agent_id") != agent_id: raise ValueError("grant_receipt_agent_mismatch")
    if p["outcome"].get("agent_id") != agent_id: raise ValueError("outcome_agent_mismatch")
    if not receipt.get("executor_id"): raise ValueError("executor_identity_required")
    if not receipt.get("executor_version"): raise ValueError("executor_version_required")
    executor_epoch=receipt.get("executor_identity_epoch")
    if not isinstance(executor_epoch,int) or executor_epoch < 1: raise ValueError("executor_identity_epoch_required")
    if receipt.get("executor_implementation_digest") and p["evidence"].get("executor_implementation_digest") not in (None, receipt.get("executor_implementation_digest")): raise ValueError("evidence_executor_digest_mismatch")
    if p["evidence"].get("executor_identity_epoch") not in (None, executor_epoch): raise ValueError("evidence_executor_epoch_mismatch")
    if p["evidence"].get("executor_id") not in (None, receipt.get("executor_id")): raise ValueError("evidence_executor_mismatch")
    if p["evidence"].get("executor_version") not in (None, receipt.get("executor_version")): raise ValueError("evidence_executor_version_mismatch")
    if p["evidence"].get("agent_id") != agent_id: raise ValueError("evidence_agent_mismatch")
    if p["evidence_manifest"].get("agent_id") != agent_id: raise ValueError("manifest_agent_mismatch")
    if p["outcome"].get("outcome_id") != p["evidence"].get("outcome_id"): raise ValueError("outcome_evidence_binding_mismatch")
    return {"proof_id":p["proof_id"],"key_id":p["key_id"],"verifier":p["outcome"]["verifier"],"outcome_id":p["outcome"].get("outcome_id")}

def verify_registry(registry):
    if registry.get("schema_version") != "attestor-registry-v1" or registry.get("algorithm") != "Ed25519": raise ValueError("invalid_attestor_registry")
    pub=b64(registry.get("issuer_public_key",""),"issuer_public_key")
    if len(pub)!=32: raise ValueError("invalid_registry_public_key")
    payload={k:registry[k] for k in ("schema_version","algorithm","registry_id","issuer_key_id","issuer_public_key","attestors")}
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(b64(registry.get("signature",""),"registry_signature"), canonical(payload).encode())
    except Exception as exc:
        raise ValueError("registry_signature_invalid") from exc
    return registry["attestors"]

def verify_attestation(attestation, proof, registry):
    required=("schema_version","algorithm","attestor_id","key_id","proof_id","verifier","issued_at","signature")
    if any(k not in attestation for k in required): raise ValueError("attestation_field_missing")
    if attestation["schema_version"] != "outcome-attestation-v1" or attestation["algorithm"] != "Ed25519": raise ValueError("invalid_attestation_schema")
    if attestation["proof_id"] != proof["proof_id"]: raise ValueError("attestation_proof_mismatch")
    records=verify_registry(registry)
    record=next((x for x in records if x.get("attestor_id")==attestation["attestor_id"]), None)
    if not record: raise ValueError("attestor_not_found")
    if record.get("status") != "ACTIVE": raise ValueError("attestor_not_active")
    if attestation["verifier"] not in record.get("allowed_verifiers",[]): raise ValueError("verifier_not_authorized_for_attestor")
    if record.get("key_id") != attestation["key_id"]: raise ValueError("attestor_key_id_mismatch")
    issued=attestation["issued_at"].replace("Z","+00:00")
    from datetime import datetime, timezone
    t=datetime.fromisoformat(issued); start=datetime.fromisoformat(record["valid_from"].replace("Z","+00:00")); end=datetime.fromisoformat(record["expires_at"].replace("Z","+00:00"))
    if not (start <= t < end): raise ValueError("attestation_outside_attestor_validity")
    payload={k:attestation[k] for k in ("schema_version","algorithm","attestor_id","key_id","proof_id","verifier","issued_at")}
    Ed25519PublicKey.from_public_bytes(b64(record["public_key"],"public_key")).verify(b64(attestation["signature"],"signature"), canonical(payload).encode())
    return True

def main():
    root=os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(root,"outcome-proof.json"),encoding="utf-8") as f: p=json.load(f)
    try:
        result=verify(p)
    except Exception as exc:
        print(f"INVALID: {exc}"); return 1
    with open(os.path.join(root,"public-key.txt"),encoding="utf-8") as f: expected=f.read().strip()
    if expected != p["public_key"]: print("INVALID: public_key_mismatch"); return 1
    att_path=os.path.join(root,"attestation.json")
    reg_path=os.path.join(root,"attestor-registry.json")
    if os.path.exists(att_path) != os.path.exists(reg_path): print("INVALID: attestation_registry_pair_mismatch"); return 1
    if os.path.exists(att_path):
        try:
            with open(att_path,encoding="utf-8") as f: att=json.load(f)
            with open(reg_path,encoding="utf-8") as f: reg=json.load(f)
            verify_attestation(att,p,reg)
        except Exception as exc:
            print(f"INVALID: {exc}"); return 1
    print("VALID")
    for k,v in result.items(): print(f"{k}={v}")
    return 0
if __name__ == "__main__": raise SystemExit(main())
'''

README = """# AegisForge Portable Proof Bundle\n\nThis directory contains a self-contained, signed outcome proof that can be verified on another machine without the AegisForge database or runtime.\n\n## Contents\n- `outcome-proof.json` — signed proof artifact.\n- `evidence-manifest.json` — evidence entries and deterministic Merkle root.\n- `public-key.txt` — Ed25519 public key used for the proof and nested capability grant.\n- `verify_bundle.py` — standalone verifier.\n- `bundle.json` — bundle metadata and hashes.\n\n## Verify\n\nRequires Python 3 and the `cryptography` package. From this directory:\n\n```bash\npython3 verify_bundle.py\n```\n\nA valid bundle prints `VALID`. Any tampering with the proof, evidence manifest, public key, or signature is rejected.\n\n## Trust boundary\n\nThis verifies cryptographic integrity, signature authenticity, grant/receipt binding, the declared outcome contract, and the evidence Merkle root. When `attestation.json` and `attestor-registry.json` are present, it also verifies the attestor registry signature, attestor authorization, validity window, verifier scope, and attestation signature. It does **not** independently establish that the original verifier was honest or that an external real-world claim is true beyond the evidence and verifier identified by the proof.\n"""

def write(path, content):
    with open(path, "w", encoding="utf-8") as f: f.write(content)

def export_bundle(proof_path, output_dir, attestation=None, registry=None):
    proof = read_outcome_proof(proof_path)
    verify_outcome_proof(proof)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    proof_dest = os.path.join(output_dir, PROOF_NAME)
    with open(proof_dest, "w", encoding="utf-8") as f:
        json.dump(proof, f, sort_keys=True, indent=2, ensure_ascii=True); f.write("\n")
    manifest_dest = os.path.join(output_dir, MANIFEST_NAME)
    with open(manifest_dest, "w", encoding="utf-8") as f:
        json.dump(proof["evidence_manifest"], f, sort_keys=True, indent=2, ensure_ascii=True); f.write("\n")
    write(os.path.join(output_dir, PUBLIC_KEY_NAME), proof["public_key"] + "\n")
    write(os.path.join(output_dir, VERIFIER_NAME), STANDALONE_VERIFIER)
    os.chmod(os.path.join(output_dir, VERIFIER_NAME), 0o755)
    write(os.path.join(output_dir, README_NAME), README)
    optional = []
    if attestation is not None or registry is not None:
        if not isinstance(attestation, dict) or not isinstance(registry, dict):
            raise ValueError("attestation_and_registry_required_together")
        if attestation.get("proof_id") != proof["proof_id"]:
            raise ValueError("attestation_proof_mismatch")
        with open(os.path.join(output_dir, ATTESTATION_NAME), "w", encoding="utf-8") as f:
            json.dump(attestation, f, sort_keys=True, indent=2, ensure_ascii=True); f.write("\n")
        with open(os.path.join(output_dir, REGISTRY_NAME), "w", encoding="utf-8") as f:
            json.dump(registry, f, sort_keys=True, indent=2, ensure_ascii=True); f.write("\n")
        optional = [ATTESTATION_NAME, REGISTRY_NAME]
    files = []
    for name in (PROOF_NAME, MANIFEST_NAME, PUBLIC_KEY_NAME, VERIFIER_NAME, README_NAME, *optional):
        with open(os.path.join(output_dir, name), "rb") as f: data=f.read()
        files.append({"name":name,"sha256":__import__("hashlib").sha256(data).hexdigest(),"size":len(data)})
    bundle = {"schema_version":BUNDLE_SCHEMA,"proof_id":proof["proof_id"],"key_id":proof["key_id"],"files":files}
    write(os.path.join(output_dir,"bundle.json"), json.dumps(bundle,sort_keys=True,indent=2)+"\n")
    return output_dir
