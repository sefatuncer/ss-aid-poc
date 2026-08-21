"""
SS-AID PoC — Credentials Module
Verifiable Credential issuance, verification, and delegation.
"""

import json
import hashlib
import time
import copy
from dataclasses import dataclass
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

from identity import AgentIdentity


@dataclass
class VerifiableCredential:
    """Represents a W3C-style Verifiable Credential."""
    raw: dict
    proof: bytes  # Ed25519 signature over canonical JSON
    issuer_did: str

    @property
    def subject_did(self) -> str:
        return self.raw["credentialSubject"]["id"]

    @property
    def capabilities(self) -> list:
        subj = self.raw["credentialSubject"]
        return subj.get("capabilities", subj.get("scope", {}).get("capabilities", []))

    @property
    def constraints(self) -> dict:
        subj = self.raw["credentialSubject"]
        return subj.get("constraints", subj.get("scope", {}))

    @property
    def valid_until(self) -> str:
        return self.raw.get("validUntil", "")

    @property
    def delegation_depth(self) -> int:
        return self.raw["credentialSubject"].get("delegationDepth", 0)

    @property
    def max_delegation_depth(self) -> int:
        return self.raw["credentialSubject"].get("maxDelegationDepth", 0)

    def is_expired(self) -> bool:
        vu = self.valid_until
        if not vu:
            return False
        from datetime import datetime, timezone
        try:
            exp = datetime.fromisoformat(vu.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except Exception:
            return False

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.raw, sort_keys=True, separators=(",", ":")).encode()


def issue_credential(
    issuer: AgentIdentity,
    subject_did: str,
    capabilities: list,
    constraints: dict,
    valid_hours: int = 24,
    max_delegation_depth: int = 3
) -> VerifiableCredential:
    """Issue an AgentCapabilityCredential."""
    now = time.time()
    raw = {
        "@context": ["https://www.w3.org/ns/credentials/v2",
                     "https://ssaid.example/v1"],
        "type": ["VerifiableCredential", "AgentCapabilityCredential"],
        "issuer": issuer.did,
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "validUntil": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                     time.gmtime(now + valid_hours * 3600)),
        "credentialSubject": {
            "id": subject_did,
            "capabilities": capabilities,
            "constraints": constraints,
            "maxDelegationDepth": max_delegation_depth,
            "delegationDepth": 0
        }
    }

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    proof = issuer.sign(canonical)

    return VerifiableCredential(raw=raw, proof=proof, issuer_did=issuer.did)


def issue_delegation(
    delegator: AgentIdentity,
    delegator_credential: VerifiableCredential,
    delegatee_did: str,
    capabilities: list,
    constraints: dict,
    valid_hours: int = 1
) -> Optional[VerifiableCredential]:
    """Issue a DelegationCredential with monotonic scope attenuation."""
    parent_caps = set(delegator_credential.capabilities)
    child_caps = set(capabilities)

    # Enforce monotonic scope attenuation
    if not child_caps.issubset(parent_caps):
        return None  # Scope widening rejected

    parent_depth = delegator_credential.delegation_depth
    max_depth = delegator_credential.max_delegation_depth

    if parent_depth >= max_depth:
        return None  # Depth limit exceeded

    # Enforce constraint attenuation
    parent_constraints = delegator_credential.constraints
    for key, value in constraints.items():
        if key in parent_constraints:
            if key == "maxTransactionValue":
                if isinstance(value, (int, float)) and value > parent_constraints[key]:
                    return None  # Constraint widening rejected

    now = time.time()
    raw = {
        "@context": ["https://www.w3.org/ns/credentials/v2",
                     "https://ssaid.example/v1"],
        "type": ["VerifiableCredential", "DelegationCredential"],
        "issuer": delegator.did,
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "validUntil": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                     time.gmtime(now + valid_hours * 3600)),
        "credentialSubject": {
            "id": delegatee_did,
            "delegatedFrom": delegator.did,
            "delegationDepth": parent_depth + 1,
            "maxDelegationDepth": max_depth,
            "scope": {
                "capabilities": capabilities,
                **constraints
            },
            "nonce": hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:16]
        }
    }

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    proof = delegator.sign(canonical)

    return VerifiableCredential(raw=raw, proof=proof, issuer_did=delegator.did)


def verify_credential(vc: VerifiableCredential, registry) -> bool:
    """Verify a credential's signature against the issuer's DID on the registry."""
    return registry.verify_signature(
        vc.issuer_did,
        vc.canonical_bytes(),
        vc.proof
    )
