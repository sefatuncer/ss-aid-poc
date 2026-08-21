"""
SS-AID PoC — Dynamic Capability Tokens
Short-lived, scope-limited authorization tokens derived from VCs.
"""

import json
import time
import hashlib
from dataclasses import dataclass
from typing import Optional

from identity import AgentIdentity, DIDRegistry
from credentials import VerifiableCredential
from pep import PolicyEnforcementPoint, ActionRequest, PEPDecision


@dataclass
class DynamicCapabilityToken:
    """A short-lived, scope-limited authorization token."""
    action_type: str
    agent_did: str
    expiry: float
    nonce: str
    signature: bytes
    timestamp: float

    def is_expired(self) -> bool:
        return time.time() > self.expiry

    def payload_bytes(self) -> bytes:
        payload = {
            "action": self.action_type,
            "did": self.agent_did,
            "exp": self.expiry,
            "nonce": self.nonce,
            "ts": self.timestamp
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class IdentityWallet:
    """
    Agent's Identity Wallet — holds DID, credentials, and generates DCTs.
    Acts as the integration point for PEP + DCT generation.
    """

    def __init__(self, identity: AgentIdentity, credential: VerifiableCredential,
                 registry: DIDRegistry):
        self.identity = identity
        self.credential = credential
        self.registry = registry
        self.pep = PolicyEnforcementPoint(credential)
        self._used_nonces: set = set()

    def request_action(self, action_type: str, parameters: dict,
                       ttl_seconds: int = 60) -> tuple[Optional[DynamicCapabilityToken], PEPDecision]:
        """
        Process an action request from the reasoning engine.
        Returns (DCT, decision) — DCT is None if action is rejected.
        """
        action = ActionRequest(
            action_type=action_type,
            parameters=parameters,
            requesting_agent_did=self.identity.did
        )

        # PEP evaluation (deterministic)
        decision = self.pep.evaluate(action)

        if not decision.allowed:
            return None, decision

        # Generate DCT
        now = time.time()
        nonce = hashlib.sha256(f"{now}{action_type}{self.identity.did}".encode()).hexdigest()[:16]

        payload = {
            "action": action_type,
            "did": self.identity.did,
            "exp": now + ttl_seconds,
            "nonce": nonce,
            "ts": now
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = self.identity.sign(payload_bytes)

        dct = DynamicCapabilityToken(
            action_type=action_type,
            agent_did=self.identity.did,
            expiry=now + ttl_seconds,
            nonce=nonce,
            signature=signature,
            timestamp=now
        )

        return dct, decision

    def verify_dct(self, dct: DynamicCapabilityToken) -> bool:
        """Verify an incoming DCT from a peer agent."""
        # Check expiry
        if dct.is_expired():
            return False

        # Check nonce freshness (prevent replay)
        if dct.nonce in self._used_nonces:
            return False
        self._used_nonces.add(dct.nonce)

        # Verify signature against registry
        return self.registry.verify_signature(
            dct.agent_did,
            dct.payload_bytes(),
            dct.signature
        )
