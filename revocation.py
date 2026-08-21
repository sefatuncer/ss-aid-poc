"""
SS-AID PoC - Revocation registry (hash-based stand-in, NOT an accumulator).

WHAT THIS IS NOT. No cryptographic accumulator is implemented here. The design
in the article specifies a public-key accumulator that yields constant-size
non-membership witnesses. This module approximates that interface with a
hash-based status registry: generate_non_revocation_proof runs a fixed number
of SHA-256 rounds to stand in for witness computation, and
verify_non_revocation_proof reads a boolean carried in the proof dictionary
rather than checking any witness against an accumulator state.

CONSEQUENCE FOR THE REPORTED NUMBERS. The revocation-check latency reported in
the article is therefore the cost of a registry lookup, not of accumulator
witness verification, and the article says so. Published measurements of real
accumulator-based verification on constrained hardware are orders of magnitude
higher. Do not read the figure produced here as an accumulator cost.

The propagation delay parameter models the window during which a revocation has
not yet reached a verifier. It is an assumption, not an observation of gossip
behaviour on a live network.
"""

import hashlib
import time
import threading
from typing import Optional


class RevocationRegistry:
    """
    Simulated credential revocation registry on the identity network.
    Uses hash-based membership proofs (approximating bilinear accumulator behavior).
    """

    def __init__(self, propagation_delay: float = 0.0):
        self._revoked: dict[str, float] = {}  # credential_hash -> revocation_time
        self._propagation_delay = propagation_delay  # seconds
        self._lock = threading.Lock()

    def credential_hash(self, credential_bytes: bytes) -> str:
        return hashlib.sha256(credential_bytes).hexdigest()

    def revoke(self, credential_bytes: bytes):
        """Revoke a credential. Propagation delay simulates decentralized registry."""
        ch = self.credential_hash(credential_bytes)
        with self._lock:
            self._revoked[ch] = time.time()

    def is_revoked(self, credential_bytes: bytes, freshness_threshold: float = 300.0) -> bool:
        """
        Check if a credential is revoked.
        Returns True if revoked AND propagation delay has elapsed.
        """
        ch = self.credential_hash(credential_bytes)
        with self._lock:
            if ch not in self._revoked:
                return False
            revocation_time = self._revoked[ch]

        # Simulate propagation delay
        elapsed = time.time() - revocation_time
        if elapsed < self._propagation_delay:
            return False  # Revocation hasn't propagated yet

        return True

    def generate_non_revocation_proof(self, credential_bytes: bytes) -> dict:
        """
        Generate a non-revocation proof.
        In a real accumulator, this would be a constant-size cryptographic proof.
        Here we simulate the computation cost with hash operations.
        """
        ch = self.credential_hash(credential_bytes)

        # Simulate accumulator witness computation (multiple hash rounds)
        witness = ch
        for _ in range(100):  # Simulate computational cost
            witness = hashlib.sha256(witness.encode()).hexdigest()

        return {
            "type": "NonRevocationProof",
            "credential_hash": ch,
            "witness": witness,
            "timestamp": time.time(),
            "is_revoked": self.is_revoked(credential_bytes)
        }

    def verify_non_revocation_proof(self, proof: dict) -> bool:
        """Verify a non-revocation proof."""
        return not proof.get("is_revoked", True)
