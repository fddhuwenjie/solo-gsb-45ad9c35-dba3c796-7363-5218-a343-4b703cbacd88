#!/usr/bin/env python3
"""Regenerate examples/revocation_review_request.json from fresh PKI material.

The target chain is Root CA -> Intermediate CA -> api.example.com. The leaf is
covered by an offline OCSP response signed by its direct issuer; the
intermediate is covered by a complete PEM CRL signed by the root. Both
assertions are fresh throughout the wide example validity window.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=timezone.utc)
THIS_UPDATE = datetime(2024, 1, 1)
NEXT_UPDATE = datetime(2035, 1, 1)
CHECK_TIME = "2030-01-01T00:00:00Z"


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject_cn, issuer_name, issuer_key, subject_key, *, is_ca):
    return (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem(value) -> str:
    return value.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def good_ocsp(cert, issuer, issuer_key):
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=issuer,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, issuer)
        .sign(issuer_key, hashes.SHA256())
    )
    return base64.b64encode(
        response.public_bytes(serialization.Encoding.DER)
    ).decode()


def main() -> None:
    root_key = new_key()
    root = issue("Example Root CA", dn("Example Root CA"), root_key, root_key,
                 is_ca=True)

    intermediate_key = new_key()
    intermediate = issue(
        "Example Intermediate CA", dn("Example Root CA"), root_key,
        intermediate_key, is_ca=True,
    )

    leaf = issue(
        "api.example.com", dn("Example Intermediate CA"), intermediate_key,
        new_key(), is_ca=False,
    )

    leaf_ocsp = good_ocsp(leaf, intermediate, intermediate_key)

    intermediate_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.subject)
        .last_update(THIS_UPDATE)
        .next_update(NEXT_UPDATE)
        .sign(root_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )

    payload = {
        "pem_certificates": [pem(leaf), pem(intermediate), pem(root)],
        "trust_roots": [fingerprint(root)],
        "endpoints": [{
            "endpoint_id": "api.example.com",
            "target_leaf_fingerprint": fingerprint(leaf),
        }],
        "ocsp_responses": [leaf_ocsp],
        "crls": [intermediate_crl],
        "check_time": CHECK_TIME,
        "max_skew_seconds": 300,
    }

    out = Path(__file__).with_name("revocation_review_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  leaf fingerprint: {fingerprint(leaf)}")
    print(f"  intermediate fingerprint: {fingerprint(intermediate)}")
    print(f"  root fingerprint: {fingerprint(root)}")


if __name__ == "__main__":
    main()
