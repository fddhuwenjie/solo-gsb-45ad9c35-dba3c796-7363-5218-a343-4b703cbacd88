"""Chain-wide offline revocation evidence review.

For every endpoint this module reconstructs the same unique signature-verified
target chain used by the normalizer, then audits each non-root certificate on
that chain against the supplied offline OCSP responses and CRLs.

Only an assertion that can be cryptographically bound to both the certificate
and its *direct chain issuer* is evidence:

* OCSP requires an exact CertID match, an issuer or authorized delegated
  responder, a valid response signature and a fresh thisUpdate/nextUpdate
  window.
* CRL requires an exact signer binding in the PEM bundle (valid signature and
  matching issuer DN), direct issuance (no indirect CRLs), a complete non-delta
  CRL, a supported scope, valid thisUpdate/nextUpdate and either a matching
  revoked entry or no entry (good).

Fresh revoked assertions take precedence. A certificate is eligible only when
it has at least one fresh good assertion, no fresh revoked/unknown assertion
and no good/revoked contradiction.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp as x509_ocsp

from .models import (
    NormalizeChainIssue,
    NormalizeFingerprintIssue,
    RevocationCertificateResult,
    RevocationEndpointResult,
    RevocationEvidence,
    RevocationEvidenceIssue,
    RevocationReviewRequest,
    RevocationReviewResult,
)
from .normalize import (
    FINGERPRINT_RE,
    NormalizeError,
    _build_issuer_edges,
    _dedupe_paths,
    _enumerate_paths,
    _find_trust_path,
    _has_second_trust_path,
    _load_pem_bundle,
    _verify_signature,
    _verify_signed_data,
    cert_fingerprint,
)
from .ocsp import (
    _cert_id_matches,
    _der_tlv_strict,
    _is_delegated_responder,
    _ocsp_time,
    _response_signature_scheme,
)

_CRL_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----",
    re.DOTALL,
)

# CRL extensions whose critical form is understood. An unknown critical CRL
# extension cannot be ignored while deriving good status from absence.
_SUPPORTED_CRITICAL_CRL_EXTENSIONS = {
    x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string,
    x509.oid.ExtensionOID.CRL_NUMBER.dotted_string,
    x509.oid.ExtensionOID.DELTA_CRL_INDICATOR.dotted_string,
    x509.oid.ExtensionOID.FRESHEST_CRL.dotted_string,
    x509.oid.ExtensionOID.ISSUING_DISTRIBUTION_POINT.dotted_string,
}

_CERT_REASON_PRIORITY = {
    "certificate_revoked": 0,
    "evidence_conflict": 1,
    "certificate_unknown": 2,
    "evidence_invalid": 3,
    "evidence_stale": 4,
    "evidence_missing": 5,
    "ok": 6,
}


@dataclass(frozen=True)
class _OcspSource:
    index: int
    der: bytes
    response: x509_ocsp.OCSPResponse


def _issue(
    evidence_type: str,
    source_index: int,
    reason: str,
    message: str,
    *,
    certificate_fingerprint: Optional[str] = None,
    issuer_fingerprint: Optional[str] = None,
    signer_fingerprint: Optional[str] = None,
    candidate_signer_fingerprints: Optional[list[str]] = None,
    this_update=None,
    next_update=None,
) -> RevocationEvidenceIssue:
    return RevocationEvidenceIssue(
        evidence_type=evidence_type,  # type: ignore[arg-type]
        source_index=source_index,
        reason=reason,
        message=message,
        certificate_fingerprint=certificate_fingerprint,
        issuer_fingerprint=issuer_fingerprint,
        signer_fingerprint=signer_fingerprint,
        candidate_signer_fingerprints=candidate_signer_fingerprints,
        this_update=this_update,
        next_update=next_update,
    )


def _issue_sort_key(issue: RevocationEvidenceIssue) -> tuple:
    return (
        0 if issue.evidence_type == "ocsp" else 1,
        issue.source_index,
        issue.reason,
        issue.certificate_fingerprint or "",
        issue.issuer_fingerprint or "",
        issue.signer_fingerprint or "",
    )


def _evidence_sort_key(evidence: RevocationEvidence) -> tuple:
    return (
        0 if evidence.evidence_type == "ocsp" else 1,
        evidence.source_index,
        evidence.status,
    )


# ---------------------------------------------------------------------------
# Chain resolution
# ---------------------------------------------------------------------------


def _resolve_chains(req: RevocationReviewRequest):
    endpoint_ids = [e.endpoint_id for e in req.endpoints]
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise NormalizeError(
            "invalid_request",
            "endpoints: endpoint_id values must be unique",
        )

    fingerprint_issues: list[NormalizeFingerprintIssue] = []
    trust_roots: set[str] = set()
    for raw in req.trust_roots:
        fp = raw.strip().lower()
        if not FINGERPRINT_RE.match(fp):
            fingerprint_issues.append(
                NormalizeFingerprintIssue(
                    fingerprint=raw, referred_by="trust_roots"
                )
            )
        else:
            trust_roots.add(fp)

    for endpoint in req.endpoints:
        fp = endpoint.target_leaf_fingerprint.strip().lower()
        if not FINGERPRINT_RE.match(fp):
            fingerprint_issues.append(
                NormalizeFingerprintIssue(
                    fingerprint=endpoint.target_leaf_fingerprint,
                    referred_by=(
                        f"endpoints['{endpoint.endpoint_id}']."
                        "target_leaf_fingerprint"
                    ),
                )
            )

    if fingerprint_issues:
        raise NormalizeError(
            "invalid_fingerprint",
            "one or more fingerprints are not 64-character hex SHA-256 values",
            fingerprint_issues=fingerprint_issues,
        )

    certs, pem_issues = _load_pem_bundle(req.pem_certificates)
    if pem_issues:
        raise NormalizeError(
            "invalid_pem",
            "one or more PEM list elements could not be parsed",
            pem_issues=pem_issues,
        )

    missing: list[NormalizeFingerprintIssue] = []
    for fp in sorted(trust_roots):
        if fp not in certs:
            missing.append(
                NormalizeFingerprintIssue(
                    fingerprint=fp, referred_by="trust_roots"
                )
            )
    for endpoint in req.endpoints:
        fp = endpoint.target_leaf_fingerprint.strip().lower()
        if fp not in certs:
            missing.append(
                NormalizeFingerprintIssue(
                    fingerprint=fp,
                    referred_by=(
                        f"endpoints['{endpoint.endpoint_id}']."
                        "target_leaf_fingerprint"
                    ),
                )
            )
    if missing:
        raise NormalizeError(
            "unknown_fingerprint",
            "some fingerprints do not match any certificate in the PEM bundle",
            fingerprint_issues=missing,
        )

    bad_roots = sorted(
        fp
        for fp in trust_roots
        if certs[fp].subject != certs[fp].issuer
        or not _verify_signature(certs[fp], certs[fp])
    )
    if bad_roots:
        raise NormalizeError(
            "trust_root_not_self_signed",
            "every declared trust root must be a self-signed certificate "
            "(subject == issuer with a valid self-signature)",
            fingerprint_issues=[
                NormalizeFingerprintIssue(
                    fingerprint=fp, referred_by="trust_roots"
                )
                for fp in bad_roots
            ],
        )

    edges = _build_issuer_edges(certs)
    roots = frozenset(trust_roots)
    resolved = {}
    for endpoint in req.endpoints:
        fp = endpoint.target_leaf_fingerprint.strip().lower()
        if fp not in resolved:
            first = _find_trust_path(fp, edges, roots)
            ambiguous = first is not None and _has_second_trust_path(
                first, edges, roots
            )
            resolved[fp] = (first, ambiguous)

    chain_issues = []
    chains = {}
    for endpoint in req.endpoints:
        fp = endpoint.target_leaf_fingerprint.strip().lower()
        first, ambiguous = resolved[fp]
        if first is not None and not ambiguous:
            chains[fp] = first
            continue
        valid, dead_ends = _enumerate_paths(fp, edges, roots)
        chain_issues.append(
            NormalizeChainIssue(
                endpoint_id=endpoint.endpoint_id,
                leaf_role="target",
                leaf=fp,
                candidate_issuers=sorted(edges.get(fp, [])),
                candidate_paths=_dedupe_paths(valid + dead_ends),
                reason="ambiguous_chain" if ambiguous else "no_trust_path",
            )
        )
    if chain_issues:
        ambiguous = any(i.reason == "ambiguous_chain" for i in chain_issues)
        raise NormalizeError(
            "ambiguous_chain" if ambiguous else "no_trust_path",
            "cross-signing leaves multiple valid paths to a declared trust root"
            if ambiguous
            else "no verified signature path from a target leaf to a trust root",
            chain_issues=chain_issues,
        )
    return certs, chains


# ---------------------------------------------------------------------------
# OCSP source parsing and single-CertID enforcement
# ---------------------------------------------------------------------------


def _count_single_responses(der: bytes) -> Optional[int]:
    """Count immediate SingleResponse elements in a successful Basic OCSP DER."""
    try:
        tag, pos, outer_end = _der_tlv_strict(der, 0, len(der))
        if tag != 0x30:
            return None
        _tag, _s, pos = _der_tlv_strict(der, pos, outer_end)
        tag, pos, rb_end = _der_tlv_strict(der, pos, outer_end)
        if tag != 0xA0:
            return None
        tag, pos, rb_end = _der_tlv_strict(der, pos, rb_end)
        if tag != 0x30:
            return None
        _tag, _s, pos = _der_tlv_strict(der, pos, rb_end)
        tag, octet_start, octet_end = _der_tlv_strict(der, pos, rb_end)
        if tag != 0x04:
            return None
        # OCTET STRING -> BasicOCSPResponse SEQUENCE -> tbsResponseData.
        tag, tbs_pos, basic_seq_end = _der_tlv_strict(
            der, octet_start, octet_end
        )
        if tag != 0x30:
            return None
        tag, tbs_content, tbs_end = _der_tlv_strict(
            der, tbs_pos, basic_seq_end
        )
        if tag != 0x30:
            return None
        q = tbs_content
        tag, _start, field_end = _der_tlv_strict(der, q, tbs_end)
        if tag == 0xA0:  # optional version
            q = field_end
            tag, _start, field_end = _der_tlv_strict(der, q, tbs_end)
        if tag not in (0xA1, 0xA2):  # responderID byName / byKey
            return None
        q = field_end
        tag, _start, field_end = _der_tlv_strict(der, q, tbs_end)
        if tag != 0x18:  # producedAt GeneralizedTime
            return None
        q = field_end
        tag, start, end = _der_tlv_strict(der, q, tbs_end)
        if tag != 0x30:  # SEQUENCE OF SingleResponse
            return None
        count = 0
        p = start
        while p < end:
            child_tag, _child_start, child_end = _der_tlv_strict(
                der, p, end
            )
            if child_tag != 0x30 or child_end > end:
                return None
            count += 1
            p = child_end
        if p != end:
            return None
        return count
    except (IndexError, ValueError):
        return None
    return None


def _ocsp_status_name(response) -> Optional[str]:
    try:
        return response.certificate_status.name.lower()
    except ValueError:
        return None


def _evaluate_ocsp_for_pair(
    source: _OcspSource,
    child_fp: str,
    issuer_fp: str,
    certs,
    check_time,
    skew,
):
    """Return (evidence, issue); exactly one is non-None for a CertID match."""
    response = source.response
    child = certs[child_fp]
    issuer = certs[issuer_fp]

    responder_name = response.responder_name
    responder_key_hash = response.responder_key_hash

    def matches_responder_id(cert) -> bool:
        if responder_name is not None:
            return cert.subject.public_bytes() == responder_name.public_bytes()
        from .ocsp import _key_hash

        try:
            return _key_hash(cert) == responder_key_hash
        except ValueError:
            return False

    if responder_name is not None:
        responder_type = "name"
    elif responder_key_hash is not None:
        responder_type = "key_hash"
    else:
        return None, _issue(
            "ocsp", source.index, "invalid_ocsp_response",
            "the response carries no responderID",
            certificate_fingerprint=child_fp, issuer_fingerprint=issuer_fp,
        )

    matching = [
        cert
        for cert in [issuer, *response.certificates]
        if matches_responder_id(cert)
    ]
    if not matching:
        return None, _issue(
            "ocsp", source.index, "responder_not_found",
            "neither the chain issuer nor an embedded responder certificate "
            "matches responderID",
            certificate_fingerprint=child_fp, issuer_fingerprint=issuer_fp,
        )

    issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    signer = None
    signer_type = None
    for cand in matching:
        if cand.public_bytes(serialization.Encoding.DER) == issuer_der:
            signer, signer_type = cand, "issuer"
            break
    if signer is None:
        for cand in matching:
            if _is_delegated_responder(cand, issuer, check_time):
                signer, signer_type = cand, "responder_certificate"
                break
    if signer is None:
        return None, _issue(
            "ocsp", source.index, "unauthorized_responder",
            "the responder is not the issuer or a directly delegated, "
            "currently valid id-kp-OCSPSigning responder",
            certificate_fingerprint=child_fp, issuer_fingerprint=issuer_fp,
        )

    scheme = _response_signature_scheme(response, source.der)
    signature_valid = scheme is not None and _verify_signed_data(
        signer.public_key(),
        response.signature,
        response.tbs_response_bytes,
        *scheme,
    )
    if not signature_valid:
        return None, _issue(
            "ocsp", source.index, "signature_invalid",
            "the OCSP response signature does not verify",
            certificate_fingerprint=child_fp, issuer_fingerprint=issuer_fp,
            signer_fingerprint=cert_fingerprint(signer),
        )

    this_update = _ocsp_time(response, "this_update")
    next_update = _ocsp_time(response, "next_update")
    produced_at = _ocsp_time(response, "produced_at")
    common = {
        "certificate_fingerprint": child_fp,
        "issuer_fingerprint": issuer_fp,
        "signer_fingerprint": cert_fingerprint(signer),
        "this_update": this_update,
        "next_update": next_update,
    }

    if produced_at is not None and produced_at > check_time + skew:
        return None, _issue(
            "ocsp", source.index, "produced_at_in_future",
            "producedAt is later than check_time plus skew",
            **common,
        )
    if next_update is None:
        return None, _issue(
            "ocsp", source.index, "next_update_missing",
            "the OCSP response omits nextUpdate", **common,
        )
    if check_time < this_update - skew:
        return None, _issue(
            "ocsp", source.index, "response_not_yet_valid",
            "check_time is before thisUpdate minus skew", **common,
        )
    if check_time > next_update + skew:
        return None, _issue(
            "ocsp", source.index, "response_stale",
            "check_time is after nextUpdate plus skew", **common,
        )

    status = _ocsp_status_name(response)
    if status not in ("good", "revoked", "unknown"):
        return None, _issue(
            "ocsp", source.index, "invalid_ocsp_response",
            "the response carries an unrecognized certificate status",
            **common,
        )

    revocation_time = None
    revocation_reason = None
    if status == "revoked":
        revocation_time = _ocsp_time(response, "revocation_time")
        try:
            if response.revocation_reason is not None:
                revocation_reason = response.revocation_reason.name
        except ValueError:
            revocation_reason = None

    evidence = RevocationEvidence(
        evidence_type="ocsp",
        source_index=source.index,
        status=status,  # type: ignore[arg-type]
        fresh=True,
        issuer_fingerprint=issuer_fp,
        signer_type=signer_type,  # type: ignore[arg-type]
        signer_fingerprint=cert_fingerprint(signer),
        responder_id_type=responder_type,  # type: ignore[arg-type]
        produced_at=produced_at,
        this_update=this_update,
        next_update=next_update,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    )
    return evidence, None


def _collect_ocsp_evidence(req, certs, pairs, check_time, skew):
    evidence_by_pair = {pair: [] for pair in pairs}
    issues_by_pair = {pair: [] for pair in pairs}
    global_issues = []

    for index, blob in enumerate(req.ocsp_responses):
        try:
            der = base64.b64decode("".join(blob.split()), validate=True)
            response = x509_ocsp.load_der_ocsp_response(der)
        except (TypeError, ValueError) as exc:
            global_issues.append(_issue(
                "ocsp", index, "invalid_ocsp_response",
                f"not valid Base64 DER OCSP: {exc}",
            ))
            continue

        if response.response_status is not x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
            global_issues.append(_issue(
                "ocsp", index, "response_not_successful",
                f"OCSP response status is {response.response_status.name.lower()}",
            ))
            continue

        count = _count_single_responses(der)
        if count is None:
            global_issues.append(_issue(
                "ocsp", index, "invalid_ocsp_response",
                "the successful OCSP response has malformed responseData",
            ))
            continue
        if count != 1:
            global_issues.append(_issue(
                "ocsp", index, "multiple_ocsp_responses_unsupported",
                f"the response contains {count} CertIDs; only single-response "
                "OCSP is supported",
            ))
            continue

        source = _OcspSource(index=index, der=der, response=response)
        matches = [
            pair for pair in pairs if _cert_id_matches(
                response, certs[pair[0]], certs[pair[1]]
            )
        ]
        if not matches:
            global_issues.append(_issue(
                "ocsp", index, "cert_id_mismatch",
                "the OCSP CertID matches no reviewed certificate/direct-issuer pair",
            ))
            continue

        for pair in matches:
            evidence, issue = _evaluate_ocsp_for_pair(
                source, pair[0], pair[1], certs, check_time, skew
            )
            if evidence is not None:
                evidence_by_pair[pair].append(evidence)
            else:
                issues_by_pair[pair].append(issue)

    return evidence_by_pair, issues_by_pair, global_issues


# ---------------------------------------------------------------------------
# CRL parsing, binding and verification
# ---------------------------------------------------------------------------


def _load_crl(blob: str):
    raw = blob.encode("utf-8", errors="replace")
    blocks = _CRL_PEM_BLOCK_RE.findall(raw)
    if blocks:
        if len(blocks) != 1:
            raise ValueError("a PEM CRL item must contain exactly one CRL block")
        return x509.load_pem_x509_crl(blocks[0])
    der = base64.b64decode("".join(blob.split()), validate=True)
    return x509.load_der_x509_crl(der)


def _is_ca_cert(cert) -> bool:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return ext.value.ca is True
    except x509.ExtensionNotFound:
        return False


def _unsupported_crl_reason(crl) -> Optional[tuple[str, str]]:
    # A v1 CRL simply has no extensions; the extension-based checks below
    # therefore accept it naturally.
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        pass
    else:
        return (
            "delta_crl_unsupported",
            "delta CRLs only update a complete base CRL and cannot be used as "
            "standalone revocation evidence",
        )

    for ext in crl.extensions:
        dotted = ext.oid.dotted_string
        if ext.critical and dotted not in _SUPPORTED_CRITICAL_CRL_EXTENSIONS:
            return (
                "unsupported_critical_crl_extension",
                f"critical CRL extension {dotted} is not supported",
            )

    for entry in crl:
        try:
            entry.extensions.get_extension_for_class(x509.CertificateIssuer)
        except x509.ExtensionNotFound:
            continue
        return (
            "indirect_crl_unsupported",
            "a revoked entry names a certificateIssuer other than the CRL "
            "issuer; indirect CRLs cannot be uniquely bound to one issuer",
        )

    try:
        idp_ext = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        )
    except x509.ExtensionNotFound:
        return None
    idp = idp_ext.value
    if idp.indirect_crl:
        return (
            "indirect_crl_unsupported",
            "indirect CRLs cannot be uniquely bound to one issuer and are not "
            "supported",
        )
    if idp.only_some_reasons:
        return (
            "partial_reason_crl_unsupported",
            "a CRL limited to onlySomeReasons cannot establish good status for "
            "other revocation reasons",
        )
    if getattr(idp, "only_contains_attribute_certs", False):
        return (
            "attribute_certificate_crl_unsupported",
            "attribute-certificate CRL scopes are not supported for X.509 "
            "public-key certificates",
        )
    return None


def _scope_contains(crl, child) -> bool:
    try:
        idp = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        ).value
    except x509.ExtensionNotFound:
        return True
    child_is_ca = _is_ca_cert(child)
    if idp.only_contains_user_certs and child_is_ca:
        return False
    if idp.only_contains_ca_certs and not child_is_ca:
        return False
    return True


def _crl_signature_valid(crl, signer) -> bool:
    try:
        return _verify_signed_data(
            signer.public_key(),
            crl.signature,
            crl.tbs_certlist_bytes,
            crl.signature_hash_algorithm,
            crl.signature_algorithm_oid.dotted_string,
            getattr(crl, "signature_algorithm_parameters", None),
        )
    except (ValueError, TypeError):
        return False


def _as_utc(value: datetime) -> datetime:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _crl_times(crl):
    this_update = getattr(crl, "last_update_utc", None)
    if this_update is None:
        this_update = crl.last_update
    next_update = getattr(crl, "next_update_utc", None)
    if next_update is None:
        next_update = crl.next_update
    return _as_utc(this_update), _as_utc(next_update)


def _revocation_reason(entry) -> Optional[str]:
    try:
        reason = entry.extensions.get_extension_for_class(
            x509.CRLReason
        ).value.reason
    except (x509.ExtensionNotFound, ValueError):
        return None
    return getattr(reason, "name", None)


def _collect_crl_evidence(req, certs, pairs, check_time, skew, global_issues):
    evidence_by_pair = {pair: [] for pair in pairs}
    issues_by_pair = {pair: [] for pair in pairs}
    fps = sorted(certs)

    for index, blob in enumerate(req.crls):
        try:
            crl = _load_crl(blob)
        except (ValueError, TypeError, base64.binascii.Error) as exc:
            global_issues.append(_issue(
                "crl", index, "invalid_crl",
                f"not valid PEM or Base64 DER CRL: {exc}",
            ))
            continue

        unsupported = _unsupported_crl_reason(crl)
        if unsupported is not None:
            reason, message = unsupported
            global_issues.append(_issue("crl", index, reason, message))
            continue

        verifiers = [fp for fp in fps if _crl_signature_valid(crl, certs[fp])]
        signers = [
            fp for fp in verifiers
            if certs[fp].subject.public_bytes() == crl.issuer.public_bytes()
        ]
        if not signers:
            global_issues.append(_issue(
                "crl", index, "crl_signer_not_found",
                "no in-bundle certificate with matching issuer DN verifies the "
                "CRL signature",
                candidate_signer_fingerprints=verifiers,
            ))
            continue
        if len(signers) > 1:
            global_issues.append(_issue(
                "crl", index, "crl_signer_ambiguous",
                "multiple in-bundle certificates with the same DN and key "
                "verify the CRL; the signer is not unique",
                candidate_signer_fingerprints=signers,
            ))
            continue

        signer_fp = signers[0]
        relevant_pairs = [pair for pair in pairs if pair[1] == signer_fp]
        if not relevant_pairs:
            global_issues.append(_issue(
                "crl", index, "crl_issuer_mismatch",
                "the CRL signer is not the direct issuer of any reviewed "
                "certificate",
                signer_fingerprint=signer_fp,
            ))
            continue

        this_update, next_update = _crl_times(crl)
        scoped_pairs = [
            pair for pair in relevant_pairs if _scope_contains(
                crl, certs[pair[0]]
            )
        ]
        if not scoped_pairs:
            for child_fp, issuer_fp in relevant_pairs:
                issues_by_pair[(child_fp, issuer_fp)].append(_issue(
                    "crl", index, "crl_scope_mismatch",
                    "the CRL issuing distribution point scope excludes this "
                    "certificate type",
                    certificate_fingerprint=child_fp,
                    issuer_fingerprint=issuer_fp,
                    signer_fingerprint=signer_fp,
                ))
            continue

        for child_fp, issuer_fp in scoped_pairs:
            child = certs[child_fp]
            common = {
                "certificate_fingerprint": child_fp,
                "issuer_fingerprint": issuer_fp,
                "signer_fingerprint": signer_fp,
                "this_update": this_update,
                "next_update": next_update,
            }
            if next_update is None:
                issues_by_pair[(child_fp, issuer_fp)].append(_issue(
                    "crl", index, "crl_next_update_missing",
                    "the CRL omits nextUpdate and has no freshness bound",
                    **common,
                ))
                continue
            if check_time < this_update - skew:
                issues_by_pair[(child_fp, issuer_fp)].append(_issue(
                    "crl", index, "crl_not_yet_valid",
                    "check_time is before CRL thisUpdate minus skew",
                    **common,
                ))
                continue
            if check_time > next_update + skew:
                issues_by_pair[(child_fp, issuer_fp)].append(_issue(
                    "crl", index, "crl_stale",
                    "check_time is after CRL nextUpdate plus skew",
                    **common,
                ))
                continue

            entry = crl.get_revoked_certificate_by_serial_number(
                child.serial_number
            )
            if entry is None:
                status = "good"
                revocation_time = None
                revocation_reason = None
            else:
                status = "revoked"
                revocation_time = _as_utc(
                    entry.revocation_date_utc
                    if hasattr(entry, "revocation_date_utc")
                    else entry.revocation_date
                )
                revocation_reason = _revocation_reason(entry)

            evidence_by_pair[(child_fp, issuer_fp)].append(RevocationEvidence(
                evidence_type="crl",
                source_index=index,
                status=status,  # type: ignore[arg-type]
                fresh=True,
                issuer_fingerprint=issuer_fp,
                signer_type="issuer",
                signer_fingerprint=signer_fp,
                this_update=this_update,
                next_update=next_update,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason,
            ))

    return evidence_by_pair, issues_by_pair


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _certificate_result(cert, child_fp, issuer_fp, evidence, issues):
    statuses = {item.status for item in evidence}
    good_issues = [i for i in issues if not i.reason.endswith("stale")]
    stale = any(i.reason.endswith("stale") for i in issues)

    if "revoked" in statuses:
        # A fresh authenticated revocation is decisive even when another
        # fresh source says good; both assertions remain listed as evidence.
        reason = "certificate_revoked"
    elif "unknown" in statuses:
        reason = "certificate_unknown"
    elif "good" in statuses:
        reason = "ok"
    elif good_issues:
        reason = "evidence_invalid"
    elif stale:
        reason = "evidence_stale"
    else:
        reason = "evidence_missing"

    return RevocationCertificateResult(
        certificate_fingerprint=child_fp,
        issuer_fingerprint=issuer_fp,
        subject=cert.subject.rfc4514_string(),
        reason=reason,  # type: ignore[arg-type]
        eligible=reason == "ok",
        evidence=sorted(evidence, key=_evidence_sort_key),
        issues=sorted(issues, key=_issue_sort_key),
    )


def review_revocation(req: RevocationReviewRequest) -> RevocationReviewResult:
    certs, chains_by_leaf = _resolve_chains(req)
    check_time = req.check_time
    skew = timedelta(seconds=req.max_skew_seconds)

    pairs = set()
    for chain in chains_by_leaf.values():
        pairs.update(zip(chain, chain[1:]))

    evidence, issues, global_issues = _collect_ocsp_evidence(
        req, certs, pairs, check_time, skew
    )
    crl_evidence, crl_issues = _collect_crl_evidence(
        req, certs, pairs, check_time, skew, global_issues
    )
    for pair, items in crl_evidence.items():
        evidence[pair].extend(items)
    for pair, items in crl_issues.items():
        issues[pair].extend(items)

    endpoint_results = []
    for endpoint in req.endpoints:
        leaf_fp = endpoint.target_leaf_fingerprint.strip().lower()
        chain = chains_by_leaf[leaf_fp]
        cert_results = []
        endpoint_issues = []

        for child_fp, issuer_fp in zip(chain, chain[1:]):
            pair = (child_fp, issuer_fp)
            pair_issues = sorted(issues[pair], key=_issue_sort_key)
            result = _certificate_result(
                certs[child_fp], child_fp, issuer_fp,
                evidence[pair], pair_issues,
            )
            cert_results.append(result)
            endpoint_issues.extend(pair_issues)

        reason = min(
            (result.reason for result in cert_results),
            key=lambda value: _CERT_REASON_PRIORITY[value],
        )
        endpoint_results.append(RevocationEndpointResult(
            endpoint_id=endpoint.endpoint_id,
            target_leaf_fingerprint=leaf_fp,
            eligible=reason == "ok",
            reason=reason,  # type: ignore[arg-type]
            chain=list(chain),
            certificates=cert_results,
            evidence_issues=endpoint_issues,
        ))

    endpoint_results.sort(key=lambda result: result.endpoint_id)
    bound_source_keys = {
        (item.evidence_type, item.source_index)
        for result in endpoint_results
        for certificate in result.certificates
        for item in certificate.evidence
    }
    bound_issue_keys = {
        (issue.evidence_type, issue.source_index)
        for result in endpoint_results
        for issue in result.evidence_issues
    } | bound_source_keys
    unbound_issues = [
        issue for issue in global_issues
        if (issue.evidence_type, issue.source_index) not in bound_issue_keys
    ]

    return RevocationReviewResult(
        check_time=check_time,
        max_skew_seconds=req.max_skew_seconds,
        results=endpoint_results,
        evidence_issues=sorted(unbound_issues, key=_issue_sort_key),
    )
