"""Tests for POST /deployments/revocation-review."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.main import app

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
client = TestClient(app)


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, issuer_cn, issuer_key, subject_key, *, ca):
    return (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def _responder(issuer, issuer_key):
    key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn("OCSP Responder"))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=30))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256()), key


def _chain():
    root_key = _key()
    root = _cert("Root CA", "Root CA", root_key, root_key, ca=True)
    intermediate_key = _key()
    intermediate = _cert(
        "Intermediate CA", "Root CA", root_key, intermediate_key, ca=True
    )
    leaf_key = _key()
    leaf = _cert(
        "api.example.com", "Intermediate CA", intermediate_key, leaf_key,
        ca=False,
    )
    return root, root_key, intermediate, intermediate_key, leaf, leaf_key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert):
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def good_ocsp(cert, issuer, issuer_key, *, this_update=NOW - timedelta(days=1),
              next_update=NOW + timedelta(days=1), status=ocsp.OCSPCertStatus.GOOD,
              revocation_time=None, responder_cert=None, signer_key=None,
              embedded=()):
    """Build an OCSP response, retrying ECDSA signatures.

    cryptography 44 serializes P-256 ECDSA OCSP signatures as though every
    signature were 73 bytes; a rare 72-byte DER signature therefore produces
    inconsistent outer lengths. Signing again quickly avoids depending on that
    library bug in these service tests.
    """
    for _attempt in range(20):
        builder = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=cert,
                issuer=issuer,
                algorithm=hashes.SHA1(),
                cert_status=status,
                this_update=this_update.replace(tzinfo=None),
                next_update=next_update.replace(tzinfo=None),
                revocation_time=(revocation_time.replace(tzinfo=None)
                                 if revocation_time else None),
                revocation_reason=(
                    x509.ReasonFlags.key_compromise
                    if status is ocsp.OCSPCertStatus.REVOKED else None
                ),
            )
        )
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.HASH,
            responder_cert if responder_cert is not None else issuer,
        )
        if embedded:
            builder = builder.certificates(list(embedded))
        response = builder.sign(
            signer_key if signer_key is not None else issuer_key,
            hashes.SHA256(),
        )
        der = response.public_bytes(serialization.Encoding.DER)
        # cryptography 44 miscomputes BasicOCSPResponse's outer lengths when an
        # ECDSA signature DER is 72 bytes; the 73-byte form serializes cleanly.
        if responder_cert is not None or len(der) == 292:
            break
    return base64.b64encode(der).decode()


def crl_b64(crl):
    return base64.b64encode(crl.public_bytes(serialization.Encoding.DER)).decode()


def good_crl(issuer, issuer_key, *, revoked=(), last_update=NOW - timedelta(days=1),
             next_update=NOW + timedelta(days=1)):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(last_update.replace(tzinfo=None))
        .next_update(next_update.replace(tzinfo=None))
    )
    for serial in revoked:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date((NOW - timedelta(days=2)).replace(tzinfo=None))
            .add_extension(
                x509.CRLReason(x509.ReasonFlags.key_compromise),
                critical=False,
            )
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    crl = builder.sign(issuer_key, hashes.SHA256())
    return crl_b64(crl)


def review(bundle, root, leaf, ocsps=(), crls=(), *, skew=0):
    return client.post(
        "/deployments/revocation-review",
        json={
            "pem_certificates": [pem(cert) for cert in bundle],
            "trust_roots": [fingerprint(root)],
            "endpoints": [{
                "endpoint_id": "api.example.com",
                "target_leaf_fingerprint": fingerprint(leaf),
            }],
            "ocsp_responses": list(ocsps),
            "crls": list(crls),
            "check_time": NOW.isoformat(),
            "max_skew_seconds": skew,
        },
    )


def cert_body(response, cert_fp):
    body = response.json()
    result = body["results"][0]
    return next(
        item for item in result["certificates"]
        if item["certificate_fingerprint"] == cert_fp
    )


def test_eligible_when_leaf_ocsp_and_intermediate_crl_are_good():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=[good_ocsp(leaf, intermediate, ik)],
        crls=[good_crl(root, _rk)],
    )
    assert r.status_code == 200, r.text
    result = r.json()["results"][0]
    assert result["eligible"] is True
    assert result["reason"] == "ok"
    assert result["chain"] == [
        fingerprint(leaf), fingerprint(intermediate), fingerprint(root)
    ]
    assert [c["certificate_fingerprint"] for c in result["certificates"]] == [
        fingerprint(leaf), fingerprint(intermediate)
    ]
    assert result["certificates"][0]["evidence"][0]["evidence_type"] == "ocsp"
    assert result["certificates"][1]["evidence"][0]["evidence_type"] == "crl"

def test_delegated_ocsp_responder_is_accepted():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    responder, responder_key = _responder(intermediate, ik)
    response = good_ocsp(
        leaf, intermediate, ik,
        responder_cert=responder,
        signer_key=responder_key,
        embedded=[responder],
    )
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=[response],
        crls=[good_crl(root, _rk)],
    )
    assert r.status_code == 200, r.text
    evidence = r.json()["results"][0]["certificates"][0]["evidence"][0]
    assert evidence["signer_type"] == "responder_certificate"
    assert evidence["signer_fingerprint"] == fingerprint(responder)


def test_revoked_crl_takes_precedence_over_fresh_good_ocsp():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=[good_ocsp(leaf, intermediate, ik)],
        crls=[good_crl(intermediate, ik, revoked=[leaf.serial_number])],
    )
    assert r.status_code == 200, r.text
    result = r.json()["results"][0]
    assert result["eligible"] is False
    assert result["reason"] == "certificate_revoked"
    leaf_result = result["certificates"][0]
    assert leaf_result["reason"] == "certificate_revoked"
    assert {item["status"] for item in leaf_result["evidence"]} == {
        "good", "revoked"
    }
    assert leaf_result["evidence"][0]["revocation_reason"] in (None, "key_compromise")


def test_missing_intermediate_evidence_fails_entire_chain():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=[good_ocsp(leaf, intermediate, ik)],
    )
    assert r.status_code == 200, r.text
    result = r.json()["results"][0]
    assert result["eligible"] is False
    assert result["reason"] == "evidence_missing"
    assert result["certificates"][1]["reason"] == "evidence_missing"


def test_stale_evidence_is_not_good():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    stale_ocsp = good_ocsp(
        leaf, intermediate, ik,
        this_update=NOW - timedelta(days=20),
        next_update=NOW - timedelta(days=10),
    )
    r = review([leaf, intermediate, root], root, leaf, ocsps=[stale_ocsp])
    assert r.status_code == 200, r.text
    leaf_result = cert_body(r, fingerprint(leaf))
    assert leaf_result["eligible"] is False
    assert leaf_result["reason"] == "evidence_stale"
    assert leaf_result["issues"][0]["reason"] == "response_stale"
    assert leaf_result["evidence"] == []


def test_skew_widens_ocsp_and_crl_windows():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=[good_ocsp(
            leaf, intermediate, ik,
            this_update=NOW - timedelta(days=2),
            next_update=NOW + timedelta(seconds=30),
        )],
        crls=[good_crl(
            root, _rk,
            last_update=NOW - timedelta(days=2),
            next_update=NOW + timedelta(seconds=30),
        )],
        skew=60,
    )
    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["eligible"] is True


def test_revoked_intermediate_crl_fails_endpoint():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=[good_ocsp(leaf, intermediate, ik)],
        crls=[good_crl(root, _rk, revoked=[intermediate.serial_number])],
    )
    assert r.status_code == 200, r.text
    result = r.json()["results"][0]
    assert result["eligible"] is False
    assert result["reason"] == "certificate_revoked"
    assert result["certificates"][1]["reason"] == "certificate_revoked"


def test_delta_and_indirect_crls_are_unsupported():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    delta = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(intermediate.subject)
        .last_update((NOW - timedelta(days=1)).replace(tzinfo=None))
        .next_update((NOW + timedelta(days=1)).replace(tzinfo=None))
        .add_extension(x509.DeltaCRLIndicator(crl_number=1), critical=False)
        .sign(ik, hashes.SHA256())
    )
    indirect = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(intermediate.subject)
        .last_update((NOW - timedelta(days=1)).replace(tzinfo=None))
        .next_update((NOW + timedelta(days=1)).replace(tzinfo=None))
        .add_extension(
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=True,
                only_contains_attribute_certs=False,
            ),
            critical=False,
        )
        .sign(ik, hashes.SHA256())
    )
    r = review(
        [leaf, intermediate, root], root, leaf,
        crls=[crl_b64(delta), crl_b64(indirect)],
    )
    assert r.status_code == 200, r.text
    reasons = {item["reason"] for item in r.json()["evidence_issues"]}
    assert "delta_crl_unsupported" in reasons
    assert "indirect_crl_unsupported" in reasons


def test_crl_signed_by_non_direct_chain_issuer_does_not_bind():
    root, root_key, intermediate, _ik, leaf, _lk = _chain()
    other_key = _key()
    other = _cert("Unrelated CA", "Unrelated CA", other_key, other_key, ca=True)
    r = review(
        [leaf, intermediate, root, other], root, leaf,
        crls=[good_crl(other, other_key)],
    )
    assert r.status_code == 200, r.text
    issue = r.json()["evidence_issues"][0]
    assert issue["reason"] == "crl_issuer_mismatch"
    assert issue["signer_fingerprint"] == fingerprint(other)


def test_invalid_evidence_is_reported_but_does_not_cause_422():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=["not-base64!!!"],
        crls=["not-base64!!!"],
    )
    assert r.status_code == 200, r.text
    reasons = {item["reason"] for item in r.json()["evidence_issues"]}
    assert "invalid_ocsp_response" in reasons
    assert "invalid_crl" in reasons


def test_ambiguous_chain_remains_request_level_422():
    root, root_key, intermediate, intermediate_key, leaf, _lk = _chain()
    # Another self-signed root cross-signs the same intermediate key, creating
    # two verified paths from the leaf to two declared trust anchors.
    other_key = _key()
    other_root = _cert("Root CA", "Root CA", other_key, other_key, ca=True)
    cross = (
        x509.CertificateBuilder()
        .subject_name(_dn("Intermediate CA"))
        .issuer_name(_dn("Root CA"))
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(other_key, hashes.SHA256())
    )
    r = client.post(
        "/deployments/revocation-review",
        json={
            "pem_certificates": [pem(c) for c in
                                 (leaf, intermediate, root, other_root, cross)],
            "trust_roots": [fingerprint(root), fingerprint(other_root)],
            "endpoints": [{
                "endpoint_id": "api.example.com",
                "target_leaf_fingerprint": fingerprint(leaf),
            }],
            "check_time": NOW.isoformat(),
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "ambiguous_chain"


def test_pem_crl_is_accepted():
    root, _rk, intermediate, ik, leaf, _lk = _chain()
    crl = good_crl(intermediate, ik)
    der = base64.b64decode(crl)
    pem_crl = x509.load_der_x509_crl(der).public_bytes(
        serialization.Encoding.PEM
    ).decode()
    r = review(
        [leaf, intermediate, root], root, leaf,
        ocsps=[good_ocsp(leaf, intermediate, ik)],
        crls=[good_crl(root, _rk), pem_crl],
    )
    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["eligible"] is True
