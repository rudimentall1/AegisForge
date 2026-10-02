from datetime import datetime, timedelta, timezone
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestor_registry import AttestorRecord, attest_outcome, create_registry
from shared.trust_evaluation import evaluate_trust


def _setup(status="ACTIVE", end=None):
    proof={"proof_id":"proof-1","outcome":{"verifier":"artifact_independent_v1"}}
    key=Ed25519PrivateKey.generate(); now=datetime.now(timezone.utc); end=end or now+timedelta(days=1)
    public=base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode("ascii")
    start = min(now, end) - timedelta(days=1)
    record=AttestorRecord("attestor-1","key-1",public,("artifact_independent_v1",),status,start.isoformat(),end.isoformat())
    registry=create_registry([record],Ed25519PrivateKey.generate()).to_dict()
    attestation=attest_outcome(proof,key,"attestor-1","key-1","artifact_independent_v1",now=now)
    return proof,attestation,registry,now


def test_trusted_active_attestor():
    p,a,r,n=_setup(); d=evaluate_trust(p,a,r,now=n); assert d.status=="TRUSTED" and d.reason=="authorized_active_attestor"

def test_missing_attestation_untrusted():
    p,_,r,n=_setup(); assert evaluate_trust(p,None,r,now=n).status=="UNTRUSTED"

def test_revoked_attestor_untrusted():
    p,a,r,n=_setup(status="REVOKED"); assert evaluate_trust(p,a,r,now=n).status=="UNTRUSTED"

def test_expired_attestor_expired():
    now=datetime.now(timezone.utc); p,a,r,_=_setup(end=now-timedelta(seconds=1)); assert evaluate_trust(p,a,r,now=now).status=="EXPIRED"

def test_wrong_verifier_untrusted():
    p,a,r,n=_setup(); a["verifier"]="other"; assert evaluate_trust(p,a,r,now=n).status=="UNTRUSTED"
